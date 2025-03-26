import { useLoaderData } from '@remix-run/react';
import { useEffect } from 'react';
import { useStore } from '@nanostores/react';
import { profileStore, initializeProfile, type Profile } from '~/lib/stores/profile';
import type { loader as rootLoader } from '~/root'; // Import the root loader type

export function useProfile() {
  const { user } = useLoaderData<typeof rootLoader>();
  const profile = useStore(profileStore);

  useEffect(() => {
    if (user?.profile) {
      initializeProfile(user.profile as Profile);
    }
  }, [user]);

  return profile;
}
