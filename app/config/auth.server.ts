import { z } from 'zod';

const envSchema = z.object({
  GITHUB_CLIENT_ID: z.string().optional(),
  GITHUB_CLIENT_SECRET: z.string().optional(),
  ALLOWED_GITHUB_USERS: z
    .string()
    .optional()
    .transform((str) => str?.split(',').map((s) => s.trim()) || []),
});

const env = envSchema.parse({
  GITHUB_CLIENT_ID: process.env.GITHUB_CLIENT_ID,
  GITHUB_CLIENT_SECRET: process.env.GITHUB_CLIENT_SECRET,
  ALLOWED_GITHUB_USERS: process.env.ALLOWED_GITHUB_USERS || '',
});

export const GITHUB_OAUTH_URL = 'https://github.com/login/oauth';
export const GITHUB_API_URL = 'https://api.github.com';
export const SESSION_COOKIE_KEY = 'github-session';

export const config = {
  clientId: env.GITHUB_CLIENT_ID || '',
  clientSecret: env.GITHUB_CLIENT_SECRET || '',
  allowedUsers: env.ALLOWED_GITHUB_USERS || [],
  callbackUrl: `${process.env.APP_URL}/auth/github/callback`,
} as const;

export const isAuthEnabled = Boolean(config.clientId && config.clientSecret && config.allowedUsers.length > 0);

export function isUserAllowed(githubUsername: string): boolean {
  return !isAuthEnabled || config.allowedUsers.includes(githubUsername);
}

export async function getGithubUser(accessToken: string) {
  const response = await fetch(`${GITHUB_API_URL}/user`, {
    headers: {
      Authorization: `Bearer ${accessToken}`,
      Accept: 'application/json',
    },
  });

  if (!response.ok) {
    throw new Error('Failed to fetch GitHub user');
  }

  return response.json();
}
