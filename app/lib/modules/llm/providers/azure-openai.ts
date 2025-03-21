import { createAzure } from '@ai-sdk/azure';
import type { LanguageModelV1 } from 'ai';
import { BaseProvider } from '~/lib/modules/llm/base-provider';
import type { ModelInfo } from '~/lib/modules/llm/types';
import type { IProviderSetting } from '~/types/model';

export default class AzureOpenAIProvider extends BaseProvider {
  name = 'AzureOpenAI';
  getApiKeyLink = 'https://ai.azure.com/';

  staticModels: ModelInfo[] = [
    { name: 'gpt-35-turbo', label: 'GPT-3.5 Turbo', provider: 'AzureOpenAI', maxTokenAllowed: 4096 },
  ];

  config = {
    apiTokenKey: 'AZURE_OPENAI_API_KEY',
    apiEndpointKey: 'AZURE_OPENAI_API_ENDPOINT',
    apiVersionKey: 'AZURE_OPENAI_API_VERSION',
    defaultApiVersion: '2024-12-01-preview',
  };

  async getDynamicModels(
    apiKeys?: Record<string, string>,
    settings?: IProviderSetting,
    serverEnv?: Record<string, string>,
  ): Promise<ModelInfo[]> {
    const { baseUrl, apiKey } = this.getProviderBaseUrlAndKey({
      apiKeys,
      providerSettings: settings,
      serverEnv: serverEnv as any,
      defaultBaseUrlKey: this.config.apiEndpointKey,
      defaultApiTokenKey: this.config.apiTokenKey,
      defaultApiVersionKey: this.config.apiVersionKey,
    });

    if (!apiKey || !baseUrl) {
      throw `Missing Api Key or Endpoint configuration for ${this.name} provider`;
    }

    const response = await fetch(`${baseUrl}/openai/deployments?api-version=2022-12-01`, {
      headers: {
        Authorization: `Bearer ${apiKey}`,
      },
    });

    const res = (await response.json()) as any;
    const staticModelIds = this.staticModels.map((m) => m.name);

    const data = res.data.filter(
      (model: any) =>
        model.object === 'deployment' &&
        (model.model.startsWith('gpt-') || model.model.startsWith('o')) &&
        !staticModelIds.includes(model.id),
    );

    return data.map((m: any) => ({
      name: m.id,
      label: `${m.model}`,
      provider: this.name,
      maxTokenAllowed: m.context_window || 32000,
    }));
  }

  getModelInstance(options: {
    model: string;
    serverEnv: Env;
    apiKeys?: Record<string, string>;
    providerSettings?: Record<string, IProviderSetting>;
  }): LanguageModelV1 {
    const { model, serverEnv, apiKeys, providerSettings } = options;

    const { apiKey, baseUrl, apiVersion } = this.getProviderBaseUrlAndKey({
      apiKeys,
      providerSettings: providerSettings?.[this.name],
      serverEnv: serverEnv as any,
      defaultBaseUrlKey: this.config.apiEndpointKey,
      defaultApiTokenKey: this.config.apiTokenKey,
      defaultApiVersionKey: this.config.apiVersionKey,
    });

    if (!apiKey || !baseUrl) {
      throw new Error(`Missing API key or Endpoint for ${this.name} provider`);
    }

    const provider = createAzure({
      apiKey,
      baseURL: baseUrl + '/openai/deployments',
      apiVersion: apiVersion || this.config.defaultApiVersion,
    });

    return provider(model);
  }
}
