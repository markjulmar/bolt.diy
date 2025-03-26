import { createCookieSessionStorage, redirect } from '@remix-run/cloudflare';
import { SESSION_COOKIE_KEY, isAuthEnabled } from '~/config/auth.server';

const sessionSecret = process.env.SESSION_SECRET || '';

if (isAuthEnabled && (!sessionSecret || sessionSecret.length < 32)) {
  throw new Error('SESSION_SECRET must be set and at least 32 characters long');
}

const sessionStorage = isAuthEnabled
  ? createCookieSessionStorage({
      cookie: {
        name: SESSION_COOKIE_KEY,
        secure: process.env.NODE_ENV === 'production',
        secrets: [sessionSecret],
        sameSite: 'lax',
        path: '/',
        maxAge: 60 * 60 * 24 * 30, // 30 days
        httpOnly: true,
      },
    })
  : null;

function assertSessionStorage() {
  if (!sessionStorage) {
    throw new Error('Session storage is not available');
  }
}

export async function getSession(request: Request) {
  if (!isAuthEnabled) {
    return null;
  }

  const cookie = request.headers.get('Cookie');
  console.log('Getting Request cookie:', {
    present: !!cookie,
    length: cookie?.length || 0,
    value: cookie ? cookie.substring(0, 50) + '...' : 'none',
  });

  assertSessionStorage();

  const session = await sessionStorage!.getSession(cookie);
  const sessionData = session.data;
  console.log('Session data:', {
    hasUserId: session.has('userId'),
    userId: session.get('userId'),
    dataSize: JSON.stringify(sessionData).length,
    keys: Object.keys(sessionData),
  });

  return session;
}

export async function createUserSession(
  request: Request,
  userId: string,
  username: string,
  avatar: string,
  redirectTo: string,
) {
  const session = await getSession(request);

  if (!session) {
    return new Response(null, {
      status: 302,
      headers: {
        Location: redirectTo,
      },
    });
  }

  console.log(
    `Creating session with userId: ${userId}, username: ${username}, avatar: ${avatar}, and redirectTo: ${redirectTo}`,
  );

  session.set('userId', userId);
  session.set('username', username);
  session.set('avatar', avatar);

  assertSessionStorage();

  const cookie = await sessionStorage!.commitSession(session);
  console.log('Session cookie details:', {
    length: cookie.length,
    value: cookie.substring(0, 50) + '...',
  });

  return new Response(null, {
    status: 302,
    headers: {
      Location: redirectTo,
      'Set-Cookie': cookie,
    },
  });
}

export async function getUserFromSession(request: Request) {
  const session = await getSession(request);

  if (!session) {
    return null;
  }

  const userId = session.get('userId');
  const username = session.get('username');
  const avatar = session.get('avatar');

  console.log('Getting user from session:', {
    hasUserId: session.has('userId'),
    userId,
    username,
    avatar,
  });

  if (!userId || !username) {
    return null;
  }

  return {
    userId,
    profile: {
      username,
      bio: '',
      avatar: avatar || '',
    },
  };
}

export async function requireUserId(request: Request, redirectTo: string = new URL(request.url).pathname) {
  if (!isAuthEnabled) {
    console.log('Auth is disabled, skipping userId check');
    return null;
  }

  const session = await getSession(request);

  if (!session) {
    return null;
  }

  const userId = session?.get('userId');
  const username = session?.get('username');

  console.log('Checking for required userId', {
    hasUserId: session?.has('userId') || false,
    userId,
    username,
  });

  if (!userId || !username) {
    const searchParams = new URLSearchParams({ redirectTo });
    throw redirect(`/login?${searchParams.toString()}`);
  }

  return userId;
}

export async function logout(request: Request) {
  const session = await getSession(request);

  if (!session) {
    return new Response(null, {
      status: 302,
      headers: { Location: '/' },
    });
  }

  console.log('Logging out user:', {
    hasUserId: session.has('userId'),
    userId: session.get('userId'),
  });

  assertSessionStorage();

  const cookie = await sessionStorage!.destroySession(session);

  return new Response(null, {
    status: 302,
    headers: {
      Location: '/login',
      'Set-Cookie': cookie,
    },
  });
}
