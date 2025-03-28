import { createAzure } from '@ai-sdk/azure';
import type { LanguageModelV1 } from 'ai';
import { BaseProvider } from '~/lib/modules/llm/base-provider';
import type { ModelInfo } from '~/lib/modules/llm/types';
import { LLMManager } from '~/lib/modules/llm/manager';
import type { IProviderSetting } from '~/types/model';

interface TokenResponse {
  access_token: string;
  expires_in: number;
  token_type: string;
}

interface AzureDeployment {
  name: string;
  properties?: {
    model?: {
      format?: string;
      name?: string;
      version?: string;
    };
    capabilities?: {
      chatCompletion?: boolean;
      maxOutputToken?: string;
    };
  };
}

interface OpenAIDeployment {
  id: string;
  model: string;
  owner: string;
  status: string;
  created_at: number;
  updated_at: number;
  object: string;
  scale_settings: {
    scale_type: 'standard' | string;
  };
}

type DeploymentType = AzureDeployment | OpenAIDeployment;

interface TokenInfo {
  token: string;
  expiresAt: number;
  scope: string;
}

export interface ManagedIdentityOptions {
  clientId: string;
  tenantId: string;
  clientSecret: string;
}

export default class AzureOpenAIProvider extends BaseProvider {
  private _tokens: TokenInfo[] = [];
  private _deploymentScope = 'https://management.azure.com/.default';
  private _openAIScope = 'https://cognitiveservices.azure.com/.default';
  private _serverEnv: Env | undefined;

  name = 'AzureOpenAI';
  getApiKeyLink = 'https://ai.azure.com/';
  supportsManagedIdentity = true;

  staticModels: ModelInfo[] = [];

  config = {
    apiTokenKey: 'AZURE_OPENAI_API_KEY',
    apiResourceNameKey: 'AZURE_OPENAI_API_NAME',
    apiVersionKey: 'AZURE_OPENAI_API_VERSION',
    defaultApiVersion: '2024-12-01-preview',
    managedIdentityClientIdKey: 'AZURE_CLIENT_ID',
    managedIdentityTenantIdKey: 'AZURE_TENANT_ID',
    managedIdentityClientSecretKey: 'AZURE_CLIENT_SECRET',
  };

  async getDynamicModels(
    apiKeys?: Record<string, string>,
    settings?: IProviderSetting,
    serverEnv?: Record<string, string>,
  ): Promise<ModelInfo[]> {
    this._serverEnv = serverEnv as any;

    const { baseUrl: resourceName, apiKey } = this.getProviderBaseUrlAndKey({
      apiKeys,
      providerSettings: settings,
      serverEnv: serverEnv as any,
      defaultBaseUrlKey: this.config.apiResourceNameKey,
      defaultApiTokenKey: this.config.apiTokenKey,
      defaultApiVersionKey: this.config.apiVersionKey,
    });

    if (apiKey && resourceName) {
      // Use API key authentication
      const response = await fetch(
        `https://${resourceName.trim()}.openai.azure.com/openai/deployments?api-version=2022-12-01`,
        {
          headers: {
            Authorization: `Bearer ${apiKey}`,
          },
        },
      );

      if (!response.ok) {
        throw new Error(`Failed to fetch deployments using API key. ${response.statusText}`);
      }

      const res: { data: OpenAIDeployment[] } = await response.json();

      return this._processDeployments(res.data);
    }

    // Use a configured app managed identity
    const { clientId, tenantId, subscriptionId, resourceGroup } = this._getAzureConfiguration(this._serverEnv);

    if (!subscriptionId || !resourceGroup || !clientId || !tenantId || !resourceName) {
      throw `Missing Api Key, Endpoint configuration, or Managed Identity for ${this.name} provider`;
    }

    const token = await this._getAccessToken(this._deploymentScope);
    const deployments = await this._getDeployments(token, subscriptionId, resourceGroup, resourceName);

    return this._processDeployments(deployments);
  }

  private async _getDeployments(
    token: string,
    subscriptionId: string,
    resourceGroup: string,
    resourceName: string,
  ): Promise<AzureDeployment[]> {
    const response = await fetch(
      `https://management.azure.com/subscriptions/${subscriptionId}/resourceGroups/${resourceGroup}/providers/Microsoft.CognitiveServices/accounts/${resourceName}/deployments?api-version=2023-05-01`,
      {
        headers: {
          Authorization: `Bearer ${token}`,
        },
      },
    );

    if (!response.ok) {
      throw new Error(`Failed to fetch deployments: ${response.statusText}`);
    }

    const data: { value: AzureDeployment[] } = await response.json();

    return data.value || [];
  }

  private _processDeployments(deployments: DeploymentType[]): ModelInfo[] {
    const modelContextWindows = [
      { id: 'gpt-35-turbo', context_window: 16385 },
      { id: 'gpt-4', context_window: 8192 },
    ];

    return deployments
      .filter((deployment) => this._isValidDeployment(deployment))
      .map((deployment) => {
        const modelName = this._getModelName(deployment);
        const matchingModel = modelContextWindows.find((model) => modelName.includes(model.id));

        return {
          name: this._getDeploymentName(deployment),
          label: this._createModelLabel(deployment),
          provider: this.name,
          maxTokenAllowed: this._getMaxTokens(deployment, matchingModel?.context_window),
        };
      });
  }

  private _isValidDeployment(deployment: DeploymentType): boolean {
    if (this._isOpenAIDeployment(deployment)) {
      return (
        deployment.object === 'deployment' && (deployment.model.startsWith('gpt-') || deployment.model.startsWith('o'))
      );
    }

    return !!deployment.properties?.capabilities?.chatCompletion;
  }

  private _isOpenAIDeployment(deployment: DeploymentType): deployment is OpenAIDeployment {
    return 'object' in deployment && 'model' in deployment;
  }

  private _getDeploymentName(deployment: DeploymentType): string {
    if (this._isOpenAIDeployment(deployment)) {
      return deployment.id;
    }

    return deployment.name;
  }

  private _getModelName(deployment: DeploymentType): string {
    if (this._isOpenAIDeployment(deployment)) {
      return deployment.model;
    }

    return deployment.properties?.model?.name || deployment.name;
  }

  private _getMaxTokens(deployment: DeploymentType, defaultWindow?: number): number {
    if (this._isOpenAIDeployment(deployment)) {
      return defaultWindow || 32000;
    }

    return deployment.properties?.capabilities?.maxOutputToken
      ? Number.parseInt(deployment.properties.capabilities.maxOutputToken)
      : defaultWindow || 32000;
  }

  private _createModelLabel(deployment: DeploymentType): string {
    if (this._isOpenAIDeployment(deployment)) {
      return deployment.model;
    }

    const model = deployment.properties?.model;

    if (!model) {
      return deployment.name;
    }

    const label = `${model.format || ''} ${model.name || ''}`.trim();

    return model.version ? `${label} (${model.version})` : label;
  }

  private async _getAccessToken(scope: string): Promise<string> {
    const existingToken = this._tokens.find((t) => t.scope === scope);

    if (existingToken && existingToken.expiresAt - 60000 > Date.now()) {
      return existingToken.token;
    }

    const { clientId, tenantId, clientSecret } = this._getAzureConfiguration(this._serverEnv);

    if (!clientId || !tenantId || !clientSecret) {
      throw new Error('Missing Azure credentials');
    }

    const response = await fetch(`https://login.microsoftonline.com/${tenantId}/oauth2/v2.0/token`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: new URLSearchParams({
        grant_type: 'client_credentials',
        client_id: clientId,
        client_secret: clientSecret,
        scope,
      }),
    });

    if (!response.ok) {
      throw new Error('Failed to get access token');
    }

    const data = (await response.json()) as TokenResponse;

    if (data.token_type !== 'Bearer') {
      throw new Error('Invalid token type returned from Azure.');
    }

    const tokenInfo: TokenInfo = {
      token: data.access_token,
      expiresAt: Date.now() + data.expires_in * 1000,
      scope,
    };

    // Remove old token for this scope if it exists
    this._tokens = this._tokens.filter((t) => t.scope !== scope);
    this._tokens.push(tokenInfo);

    return tokenInfo.token;
  }

  private _getAzureConfiguration(serverEnv?: Env) {
    const manager = LLMManager.getInstance();

    return {
      clientId: serverEnv?.AZURE_CLIENT_ID || process?.env?.AZURE_CLIENT_ID || manager.env?.AZURE_CLIENT_ID,
      tenantId: serverEnv?.AZURE_TENANT_ID || process?.env?.AZURE_TENANT_ID || manager.env?.AZURE_TENANT_ID,
      clientSecret:
        serverEnv?.AZURE_CLIENT_SECRET || process?.env?.AZURE_CLIENT_SECRET || manager.env?.AZURE_CLIENT_SECRET,
      resourceName:
        serverEnv?.AZURE_OPENAI_API_NAME || process?.env?.AZURE_OPENAI_API_NAME || manager.env?.AZURE_OPENAI_API_NAME,
      subscriptionId:
        serverEnv?.AZURE_SUBSCRIPTION_ID || process?.env?.AZURE_SUBSCRIPTION_ID || manager.env?.AZURE_SUBSCRIPTION_ID,
      resourceGroup:
        serverEnv?.AZURE_RESOURCE_GROUP_NAME ||
        process?.env?.AZURE_RESOURCE_GROUP_NAME ||
        manager.env?.AZURE_RESOURCE_GROUP_NAME,
    };
  }

  private _fetchWithBearerAuth():
    | ((request: RequestInfo | URL, init?: RequestInit<RequestInitCfProperties>) => Promise<Response>)
    | undefined {
    return async (request: RequestInfo | URL, init?: RequestInit<RequestInitCfProperties>): Promise<Response> => {
      const token = await this._getAccessToken(this._openAIScope);

      if (!token) {
        throw new Error('No available access token for API.');
      }

      const allHeaders: Headers = new Headers({
        ...init?.headers,
        Authorization: `Bearer ${token}`,
      });
      allHeaders.delete('api-key');

      return fetch(request, {
        ...init,
        headers: allHeaders,
      });
    };
  }

  getModelInstance(options: {
    model: string;
    serverEnv: Env;
    apiKeys?: Record<string, string>;
    providerSettings?: Record<string, IProviderSetting>;
  }): LanguageModelV1 {
    const { model, serverEnv, apiKeys, providerSettings } = options;
    this._serverEnv = serverEnv;

    const {
      apiKey,
      baseUrl: resourceName,
      apiVersion,
    } = this.getProviderBaseUrlAndKey({
      apiKeys,
      providerSettings: providerSettings?.[this.name],
      serverEnv: serverEnv as any,
      defaultBaseUrlKey: this.config.apiResourceNameKey,
      defaultApiTokenKey: this.config.apiTokenKey,
      defaultApiVersionKey: this.config.apiVersionKey,
    });

    if (apiKey && resourceName) {
      const provider = createAzure({
        apiKey,
        baseURL: `https://${resourceName.trim()}.openai.azure.com/openai/deployments`,
        apiVersion: apiVersion || this.config.defaultApiVersion,
      });

      return provider(model);
    }

    const { clientId } = this._getAzureConfiguration(serverEnv);

    if (!clientId || !resourceName) {
      throw new Error(`Missing Api key or Managed Identity for ${this.name} provider`);
    }

    const provider = createAzure({
      apiKey: clientId,
      resourceName,
      apiVersion: apiVersion || this.config.defaultApiVersion,
      fetch: this._fetchWithBearerAuth(),
    });

    return provider(model);
  }
}
