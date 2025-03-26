import type { LoaderFunctionArgs } from '@remix-run/cloudflare';
import { config, GITHUB_OAUTH_URL, getGithubUser, isUserAllowed } from '~/config/auth.server';
import { createUserSession } from '~/utils/session.server';

interface GitHubTokenResponse {
  access_token: string;
  error?: string;
  error_description?: string;
}

interface GitHubUser {
  login: string;
  id: number;
  avatar_url?: string;
}

export async function loader({ request }: LoaderFunctionArgs) {
  const url = new URL(request.url);
  const code = url.searchParams.get('code');
  const redirectTo = url.searchParams.get('redirectTo') || '/';
  const error = url.searchParams.get('error');
  const errorDescription = url.searchParams.get('error_description');

  console.log('GitHub callback received:', {
    code,
    redirectTo,
    error,
    errorDescription,
  });

  if (error) {
    console.error('GitHub OAuth error:', { error, errorDescription });
    return new Response(JSON.stringify({ error: `GitHub authentication failed: ${errorDescription || error}` }), {
      status: 403,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  if (!code) {
    console.error('No code provided in callback');
    return new Response(JSON.stringify({ error: 'No code provided' }), {
      status: 400,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  try {
    const tokenResponse = await fetch(`${GITHUB_OAUTH_URL}/access_token`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Accept: 'application/json',
      },
      body: JSON.stringify({
        client_id: config.clientId,
        client_secret: config.clientSecret,
        code,
        redirect_uri: config.callbackUrl,
      }),
    });

    const tokenData = (await tokenResponse.json()) as GitHubTokenResponse;

    if (!tokenResponse.ok) {
      console.error('Failed to get access token:', {
        status: tokenResponse.status,
        statusText: tokenResponse.statusText,
        error: tokenData.error,
        errorDescription: tokenData.error_description,
      });

      throw new Error(
        `Failed to get access token: ${tokenData.error_description || tokenData.error || tokenResponse.statusText}`,
      );
    }

    const githubUser = (await getGithubUser(tokenData.access_token)) as GitHubUser;
    const isAllowed = await isUserAllowed(githubUser.login);

    console.log(`GitHub user: ${githubUser.login}, isAllowed: ${isAllowed}`);

    if (!isAllowed) {
      return new Response(JSON.stringify({ error: 'You are not authorized to access this application' }), {
        status: 403,
        headers: { 'Content-Type': 'application/json' },
      });
    }

    console.log('Redirecting to:', redirectTo);

    return createUserSession(
      request,
      githubUser.id.toString(),
      githubUser.login,
      githubUser.avatar_url || '',
      redirectTo,
    );
  } catch (error) {
    console.error('GitHub auth error:', {
      error: error instanceof Error ? error.message : 'Unknown error',
      stack: error instanceof Error ? error.stack : undefined,
    });

    return new Response(
      JSON.stringify({
        error: 'Authentication failed',
        details: error instanceof Error ? error.message : 'Unknown error',
      }),
      { status: 500, headers: { 'Content-Type': 'application/json' } },
    );
  }
}
