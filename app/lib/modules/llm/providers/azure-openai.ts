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
}

const deploymentScope = 'https://management.azure.com/.default';
const openAIScope = 'https://cognitiveservices.azure.com/.default';

export default class AzureOpenAIProvider extends BaseProvider {
  private _tokens: TokenInfo[] = [];
  private _serverEnv: Env | undefined;
  private _providerSettings: IProviderSetting | undefined;

  name = 'AzureOpenAI';
  getApiKeyLink = 'https://ai.azure.com/';

  staticModels: ModelInfo[] = [];

  config = {
    apiTokenKey: 'AZURE_OPENAI_API_KEY',
    baseUrlKey: 'AZURE_OPENAI_API_BASE_URL',
    deploymentNameKey: 'AZURE_OPENAI_API_DEPLOYMENT_NAME',
    apiVersionKey: 'AZURE_OPENAI_API_VERSION',
    defaultApiVersion: '2024-12-01-preview',
    managedIdentityClientIdKey: 'AZURE_CLIENT_ID',
    managedIdentityTenantIdKey: 'AZURE_TENANT_ID',
    managedIdentityClientSecretKey: 'AZURE_CLIENT_SECRET',
    subscriptionIdKey: 'AZURE_SUBSCRIPTION_ID',
    resourceGroupKey: 'AZURE_RESOURCE_GROUP_NAME',
  };

  /**
   * Retrieves and processes Azure configuration settings from various sources.
   * This method consolidates configuration from:
   * 1. Provider settings (if provided)
   * 2. Server environment variables
   * 3. Process environment variables
   * 4. LLM Manager environment variables
   *
   * The method handles URL normalization and ensures consistent configuration
   * across different authentication methods (API Key and Managed Identity).
   *
   * @param options - Configuration options
   * @param options.providerSettings - Optional provider-specific settings
   * @param options.serverEnv - Optional server environment variables
   * @returns Object containing all Azure configuration values
   */
  private _getAzureConfiguration(options: { providerSettings?: IProviderSetting; serverEnv?: Record<string, string> }) {
    const { providerSettings, serverEnv } = options;
    let settingsBaseUrl = providerSettings?.baseUrl;

    if (settingsBaseUrl && settingsBaseUrl.length == 0) {
      settingsBaseUrl = undefined;
    }

    const manager = LLMManager.getInstance();
    const baseUrlKey = this.config.baseUrlKey;

    let baseUrl = settingsBaseUrl || serverEnv?.[baseUrlKey] || process?.env?.[baseUrlKey] || manager.env?.[baseUrlKey];

    if (baseUrl && baseUrl.endsWith('/')) {
      baseUrl = baseUrl.slice(0, -1);
    }

    const clientIdKey = this.config.managedIdentityClientIdKey;
    const clientId = serverEnv?.[clientIdKey] || process?.env?.[clientIdKey] || manager.env?.[clientIdKey];

    const tenantIdKey = this.config.managedIdentityTenantIdKey;
    const tenantId = serverEnv?.[tenantIdKey] || process?.env?.[tenantIdKey] || manager.env?.[tenantIdKey];

    const clientSecretKey = this.config.managedIdentityClientSecretKey;
    const clientSecret =
      serverEnv?.[clientSecretKey] || process?.env?.[clientSecretKey] || manager.env?.[clientSecretKey];

    const apiVersionKey = this.config.apiVersionKey;
    const apiVersion = serverEnv?.[apiVersionKey] || process?.env?.[apiVersionKey] || manager.env?.[apiVersionKey];

    const deploymentNameKey = this.config.deploymentNameKey;
    const deploymentName =
      serverEnv?.[deploymentNameKey] || process?.env?.[deploymentNameKey] || manager.env?.[deploymentNameKey];

    const subscriptionIdKey = this.config.subscriptionIdKey;
    const subscriptionId =
      serverEnv?.[subscriptionIdKey] || process?.env?.[subscriptionIdKey] || manager.env?.[subscriptionIdKey];

    const resourceGroupKey = this.config.resourceGroupKey;
    const resourceGroup =
      serverEnv?.[resourceGroupKey] || process?.env?.[resourceGroupKey] || manager.env?.[resourceGroupKey];

    return {
      baseUrl,
      clientId,
      tenantId,
      clientSecret,
      subscriptionId,
      resourceGroup,
      deploymentName,
      apiVersion,
    };
  }

  /**
   * Retrieves available Azure OpenAI model deployments.
   * This function supports two authentication methods:
   * 1. API Key authentication - Uses the provided API key to fetch deployments directly
   * 2. Managed Identity - Uses Azure Managed Identity to authenticate and fetch deployments
   *
   * @param apiKeys - Optional record of API keys
   * @param settings - Optional provider settings
   * @param serverEnv - Optional server environment variables
   * @returns Promise<ModelInfo[]> - Array of available model deployments with their configurations
   * @throws Error if authentication fails or required configuration is missing
   */
  async getDynamicModels(
    apiKeys?: Record<string, string>,
    settings?: IProviderSetting,
    serverEnv?: Record<string, string>,
  ): Promise<ModelInfo[]> {
    this._serverEnv = serverEnv as any;
    this._providerSettings = settings;

    const azureKeyConfig = this.getProviderBaseUrlAndKey({
      apiKeys,
      providerSettings: settings,
      serverEnv: serverEnv as any,
      defaultBaseUrlKey: this.config.baseUrlKey,
      defaultApiTokenKey: this.config.apiTokenKey,
    });

    if (azureKeyConfig.apiKey && azureKeyConfig.baseUrl) {
      // Use API key authentication
      const response = await fetch(
        `${azureKeyConfig.baseUrl.replace(/\/$/, '')}/openai/deployments?api-version=2022-12-01`,
        {
          headers: {
            Authorization: `Bearer ${azureKeyConfig.apiKey}`,
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
    const azureConfig = this._getAzureConfiguration({
      providerSettings: settings,
      serverEnv: serverEnv as any,
    });

    if (
      !azureConfig.subscriptionId ||
      !azureConfig.resourceGroup ||
      !azureConfig.clientId ||
      !azureConfig.tenantId ||
      !azureConfig.baseUrl
    ) {
      throw `Missing Api Key, Endpoint configuration, or Managed Identity for ${this.name} provider`;
    }

    const token = await this._getAccessToken(deploymentScope);
    const deployments = await this._getDeployments(
      token,
      _getResourceNameFromUrl(azureConfig.baseUrl),
      azureConfig.subscriptionId,
      azureConfig.resourceGroup,
    );

    return this._processDeployments(deployments);
  }

  private async _getDeployments(
    token: string,
    resourceName: string,
    subscriptionId: string,
    resourceGroup: string,
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
      { id: 'gpt-4o', context_window: 8000 },
      { id: 'gpt-4o-mini', context_window: 8000 },
      { id: 'gpt-4-turbo', context_window: 8000 },
      { id: 'gpt-4', context_window: 8000 },
      { id: 'gpt-3.5-turbo', context_window: 8000 },
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

    const { clientId, tenantId, clientSecret } = this._getAzureConfiguration({
      providerSettings: this._providerSettings,
      serverEnv: this._serverEnv as any,
    });

    if (!clientId || !tenantId) {
      throw new Error('Missing Azure credentials');
    }

    let data: TokenResponse;

    if (clientSecret) {
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

      data = (await response.json()) as TokenResponse;
    } else {
      // Use Managed Identity via the MSI endpoint
      const resource = scope.endsWith('.default') ? scope.slice(0, -8) : scope;
      let msiUrl = `http://169.254.169.254/metadata/identity/oauth2/token?api-version=2019-08-01&resource=${encodeURIComponent(resource)}`;

      if (clientId) {
        msiUrl += `&client_id=${encodeURIComponent(clientId)}`;
      }

      const response = await fetch(msiUrl, {
        method: 'GET',
        headers: { Metadata: 'true' },
      });

      if (!response.ok) {
        throw new Error(`Failed to get managed identity token: ${response.statusText}`);
      }

      data = await response.json();
    }

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

  private _fetchWithBearerAuth():
    | ((request: RequestInfo | URL, init?: RequestInit<RequestInitCfProperties>) => Promise<Response>)
    | undefined {
    return async (request: RequestInfo | URL, init?: RequestInit<RequestInitCfProperties>): Promise<Response> => {
      const token = await this._getAccessToken(openAIScope);

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
    this._providerSettings = providerSettings?.[this.name];

    const apiKeyConfig = this.getProviderBaseUrlAndKey({
      apiKeys,
      providerSettings: this._providerSettings,
      serverEnv: serverEnv as any,
      defaultBaseUrlKey: this.config.baseUrlKey,
      defaultApiTokenKey: this.config.apiTokenKey,
    });

    const { clientId, apiVersion } = this._getAzureConfiguration({
      providerSettings: this._providerSettings,
      serverEnv: this._serverEnv as any,
    });

    if (apiKeyConfig.apiKey && apiKeyConfig.baseUrl) {
      const provider = createAzure({
        apiKey: apiKeyConfig.apiKey,
        baseURL: `${apiKeyConfig.baseUrl.replace(/\/$/, '')}/openai/deployments`,
        apiVersion: apiVersion || this.config.defaultApiVersion,
      });

      return provider(model);
    }

    if (!clientId || !apiKeyConfig.baseUrl) {
      throw new Error(`Missing Api key or Managed Identity for ${this.name} provider`);
    }

    const provider = createAzure({
      apiKey: clientId,
      resourceName: _getResourceNameFromUrl(apiKeyConfig.baseUrl),
      apiVersion: apiVersion || this.config.defaultApiVersion,
      fetch: this._fetchWithBearerAuth(),
    });

    return provider(model);
  }
}

function _getResourceNameFromUrl(_baseUrl: string): string {
  const url = new URL(_baseUrl);
  const hostnameParts = url.hostname.split('.');

  return hostnameParts[0];
}
