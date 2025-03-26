import { atom } from 'nanostores';

export interface Profile {
  username: string;
  bio: string;
  avatar: string;
}

// Only handle localStorage on the client side
export const profileStore = atom<Profile>({
  username: '',
  bio: '',
  avatar: '',
});

// Add a function to initialize the store with server data
export const initializeProfile = (serverProfile: Profile) => {
  profileStore.set(serverProfile);

  // Now also save to localStorage
  if (typeof window !== 'undefined') {
    localStorage.setItem('bolt_profile', JSON.stringify(serverProfile));
  }
};

export const updateProfile = (updates: Partial<Profile>) => {
  profileStore.set({ ...profileStore.get(), ...updates });

  if (typeof window !== 'undefined') {
    localStorage.setItem('bolt_profile', JSON.stringify(profileStore.get()));
  }
};
