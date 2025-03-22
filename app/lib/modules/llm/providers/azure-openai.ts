import { createAzure } from '@ai-sdk/azure';
import type { LanguageModelV1 } from 'ai';
import { BaseProvider } from '~/lib/modules/llm/base-provider';
import type { ModelInfo } from '~/lib/modules/llm/types';
import { LLMManager } from '~/lib/modules/llm/manager';
import type { IProviderSetting } from '~/types/model';
import { CognitiveServicesManagementClient, type Deployment } from '@azure/arm-cognitiveservices';
import { ClientSecretCredential, type AccessToken } from '@azure/identity';
import { createScopedLogger } from '~/utils/logger';

export interface ManagedIdentityOptions {
  clientId: string;
  tenantId: string;
  clientSecret: string;
}

const logger = createScopedLogger('AzureOpenAIProvider');

export default class AzureOpenAIProvider extends BaseProvider {
  private _accessToken: AccessToken | undefined;
  private _scope = 'https://cognitiveservices.azure.com/.default';
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

    /*
     * We can auth either with an API key, or a managed identity.
     * API keys is easiest - try that first.
     */
    const { baseUrl: resourceName, apiKey } = this.getProviderBaseUrlAndKey({
      apiKeys,
      providerSettings: settings,
      serverEnv: serverEnv as any,
      defaultBaseUrlKey: this.config.apiResourceNameKey,
      defaultApiTokenKey: this.config.apiTokenKey,
      defaultApiVersionKey: this.config.apiVersionKey,
    });

    if (apiKey && resourceName) {
      // Use the deployments API to get the models.
      const response = await fetch(
        `https://${resourceName.trim()}.openai.azure.com/openai/deployments?api-version=2022-12-01`,
        {
          headers: {
            Authorization: `Bearer ${apiKey}`,
          },
        },
      );

      const res = (await response.json()) as any;

      const data = res.data.filter(
        (model: any) =>
          model.object === 'deployment' && (model.model.startsWith('gpt-') || model.model.startsWith('o')),
      );

      const modelContextWindows = [
        {
          id: 'gpt-35-turbo',
          context_window: 16385,
        },
        {
          id: 'gpt-4',
          context_window: 8192,
        },
      ];

      return data.map((m: any) => {
        const matchingModel = modelContextWindows.find(
          (model) => m.model.includes(model.id) || m.id.includes(model.id),
        );

        return {
          name: m.id,
          label: `${m.model}`,
          provider: this.name,
          maxTokenAllowed: matchingModel?.context_window || m.context_window || 32000,
        };
      });
    }

    // Try managed identity
    const { clientId, tenantId, subscriptionId, resourceGroup } = this._getAzureConfiguration(this._serverEnv);

    if (!subscriptionId || !resourceGroup || !clientId || !tenantId || !resourceName) {
      throw `Missing Api Key, Endpoint configuration, or Managed Identity for ${this.name} provider`;
    }

    const client = new CognitiveServicesManagementClient(this._getAzureCredentials(serverEnv as any), subscriptionId);
    const models: ModelInfo[] = [];

    for await (const deployment of client.deployments.list(resourceGroup, resourceName)) {
      if (deployment.name && deployment.properties?.capabilities?.chatCompletion) {
        models.push({
          name: deployment.name,
          label: this._createModelLabel(deployment) || deployment.name,
          provider: this.name,
          maxTokenAllowed: deployment.properties?.capabilities?.maxOutputToken
            ? Number.parseInt(deployment.properties.capabilities.maxOutputToken)
            : 32000,
        });
      }
    }

    return models;
  }

  private _createModelLabel = (deployment: Deployment): string | undefined => {
    const model = deployment.properties?.model;

    if (model) {
      const label = `${model.format} ${model.name}`;

      if (!model.version) {
        return label;
      }

      return `${label} (${model.version})`;
    }

    return undefined;
  };

  private _isTokenExpired(): boolean {
    // 60 seconds left?
    return !this._accessToken || this._accessToken.expiresOnTimestamp - 60000 < Date.now();
  }

  private _getAccessToken = async (): Promise<string> => {
    const { clientId, tenantId, clientSecret } = this._getAzureConfiguration(this._serverEnv);

    if (!clientId || !tenantId || !clientSecret) {
      return '';
    }

    if (this._isTokenExpired()) {
      logger.debug('Azure token expired, refreshing...');
      this._accessToken = await this._getAzureCredentials(this._serverEnv).getToken(this._scope);
    }

    return this._accessToken?.token || '';
  };

  private _getAzureCredentials = (serverEnv?: Env): ClientSecretCredential => {
    const { clientId, tenantId, clientSecret } = this._getAzureConfiguration(serverEnv);

    return new ClientSecretCredential(tenantId, clientId, clientSecret);
  };

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
    if (!this._getAccessToken) {
      return undefined;
    }

    return async (request: RequestInfo | URL, init?: RequestInit<RequestInitCfProperties>): Promise<Response> => {
      if (!this._getAccessToken) {
        throw new Error("getAccessToken is not defined in the provider's instance");
      }

      const token = await this._getAccessToken();

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
