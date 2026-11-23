import { initializeApp, getApps, cert } from 'firebase-admin/app';
import { getAuth } from 'firebase-admin/auth';
import { firebaseConfig } from './firebase-config.ts';

let hasAdminCredentials = false;

if (!getApps().length) {
  const raw = process.env.FIREBASE_SERVICE_ACCOUNT_JSON;
  if (raw) {
    try {
      initializeApp({
        credential: cert(JSON.parse(raw)),
        projectId: firebaseConfig.projectId,
      });
      hasAdminCredentials = true;
    } catch {
      console.error('FIREBASE_SERVICE_ACCOUNT_JSON is set but invalid; continuing without admin credentials.');
      initializeApp({ projectId: firebaseConfig.projectId });
    }
  } else {
    initializeApp({ projectId: firebaseConfig.projectId });
  }
}

export const adminAuth = getAuth();
// Revocation checks need admin credentials. Without them, verify the token signature only.
export const CHECK_REVOKED = hasAdminCredentials;
