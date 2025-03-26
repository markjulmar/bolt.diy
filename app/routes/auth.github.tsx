import { redirect } from '@remix-run/cloudflare';
import { config, GITHUB_OAUTH_URL } from '~/config/auth.server';

export async function loader() {
  const params = new URLSearchParams({
    client_id: config.clientId,
    redirect_uri: config.callbackUrl,
    scope: 'read:user',
    state: crypto.randomUUID(),
  });

  return redirect(`${GITHUB_OAUTH_URL}/authorize?${params.toString()}`);
}
