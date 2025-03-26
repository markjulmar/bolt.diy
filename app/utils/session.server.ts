import { createCookieSessionStorage, redirect } from '@remix-run/cloudflare';
import { SESSION_COOKIE_KEY } from '~/config/auth.server';

const sessionSecret = process.env.SESSION_SECRET;

if (!sessionSecret) {
  throw new Error('SESSION_SECRET must be set');
}

// Validate session secret length and complexity
if (sessionSecret.length < 32) {
  throw new Error('SESSION_SECRET must be at least 32 characters long');
}

// Check if the secret contains at least 8 unique characters for security
const uniqueChars = new Set(sessionSecret).size;

if (uniqueChars < 8) {
  throw new Error('SESSION_SECRET must contain at least 8 unique characters');
}

export const sessionStorage = createCookieSessionStorage({
  cookie: {
    name: SESSION_COOKIE_KEY,
    secure: process.env.NODE_ENV === 'production',
    secrets: [sessionSecret],
    sameSite: 'lax',
    path: '/',
    maxAge: 60 * 60 * 24 * 30, // 30 days
    httpOnly: true,
  },
});

const { getSession: getSessionFromStorage } = sessionStorage;

export async function getSession(request: Request) {
  const cookie = request.headers.get('Cookie');
  console.log('Getting Request cookie:', {
    present: cookie ? 'yes' : 'no',
    length: cookie?.length || 0,
    value: cookie ? cookie.substring(0, 50) + '...' : 'none',
  });

  const session = await getSessionFromStorage(cookie);
  const sessionData = session.data;
  console.log('Session data:', {
    hasUserId: session.has('userId'),
    userId: session.get('userId'),
    dataSize: JSON.stringify(sessionData).length,
    keys: Object.keys(sessionData),
  });

  return session;
}

export async function createUserSession(request: Request, userId: string, redirectTo: string) {
  const session = await getSession(request);

  console.log(`Creating session with userId: ${userId} and redirectTo: ${redirectTo}`);
  session.set('userId', userId);

  const cookie = await sessionStorage.commitSession(session);
  console.log('Session cookie details:', {
    length: cookie.length,
    value: cookie.substring(0, 50) + '...', // Log first 50 chars for debugging
  });

  const response = new Response(null, {
    status: 302,
    headers: {
      Location: redirectTo,
      'Set-Cookie': cookie,
    },
  });

  return response;
}

export async function getUserFromSession(request: Request) {
  const session = await getSession(request);
  const userId = session.get('userId');
  console.log('Getting user from session:', {
    hasUserId: session.has('userId'),
    userId,
  });

  if (!userId || typeof userId !== 'string') {
    return null;
  }

  return userId;
}

export async function requireUserId(request: Request, redirectTo: string = new URL(request.url).pathname) {
  const session = await getSession(request);
  const userId = session.get('userId');
  console.log('Requiring user ID:', {
    hasUserId: session.has('userId'),
    userId,
    type: typeof userId,
  });

  if (!userId || typeof userId !== 'string') {
    const searchParams = new URLSearchParams([['redirectTo', redirectTo]]);
    throw redirect(`/login?${searchParams}`);
  }

  return userId;
}

export async function logout(request: Request) {
  const session = await getSession(request);
  console.log('Logging out user:', {
    hasUserId: session.has('userId'),
    userId: session.get('userId'),
  });

  return redirect('/', {
    headers: {
      'Set-Cookie': await sessionStorage.destroySession(session),
    },
  });
}
