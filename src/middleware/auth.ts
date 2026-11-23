import { NextFunction, Request, Response } from 'express';
import { DecodedIdToken } from 'firebase-admin/auth';
import { adminAuth, CHECK_REVOKED } from '../lib/firebase-admin.ts';
import { getOrCreateUser } from '../db/users.ts';

export type DbUser = Awaited<ReturnType<typeof getOrCreateUser>>;

export interface AuthRequest extends Request {
  firebaseUser?: DecodedIdToken;
  currentUser?: DbUser;
}

export const requireAuth = async (
  req: AuthRequest,
  res: Response,
  next: NextFunction
) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Authentication required.' });
  }

  const token = authHeader.slice('Bearer '.length).trim();
  if (!token) {
    return res.status(401).json({ error: 'Authentication token missing.' });
  }

  let decodedToken: DecodedIdToken;
  try {
    decodedToken = await adminAuth.verifyIdToken(token, CHECK_REVOKED);
  } catch (error) {
    console.error('Auth verification error:', error);
    return res.status(401).json({ error: 'Invalid or expired session token.' });
  }

  req.firebaseUser = decodedToken;

  const emailVerified = decodedToken.email_verified === true;
  let dbUser: DbUser;
  try {
    dbUser = await getOrCreateUser({
      uid: decodedToken.uid,
      email: decodedToken.email || '',
      emailVerified,
      displayName: decodedToken.name,
      avatarUrl: decodedToken.picture,
    });
  } catch (error) {
    console.error('Database error during auth:', error);
    return res.status(503).json({
      error: 'Database is temporarily unavailable. Please try again.',
      code: 'DB_UNAVAILABLE',
    });
  }

  if (dbUser.isRestricted) {
    return res.status(403).json({
      error: 'Your account is currently restricted by campus moderation.',
      code: 'ACCOUNT_RESTRICTED',
    });
  }

  if (dbUser.verificationStatus === 'verified' && !emailVerified) {
    console.warn('[SECURITY_AUDIT] LEGACY_VERIFIED_WITH_UNVERIFIED_EMAIL', {
      userId: dbUser.id,
      role: dbUser.role,
    });
  }

  req.currentUser = dbUser;
  next();
};

export const optionalAuth = async (
  req: AuthRequest,
  res: Response,
  next: NextFunction
) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return next();
  }

  const token = authHeader.slice('Bearer '.length).trim();
  if (!token) {
    return next();
  }

  let decodedToken: DecodedIdToken;
  try {
    decodedToken = await adminAuth.verifyIdToken(token, CHECK_REVOKED);
  } catch {
    // Proceed as unauthenticated viewer when optional token is invalid
    return next();
  }

  let dbUser: DbUser;
  try {
    dbUser = await getOrCreateUser({
      uid: decodedToken.uid,
      email: decodedToken.email || '',
      emailVerified: decodedToken.email_verified === true,
      displayName: decodedToken.name,
      avatarUrl: decodedToken.picture,
    });
  } catch (error) {
    console.error('Database error during auth:', error);
    // Proceed as unauthenticated viewer when database is temporarily unavailable
    return next();
  }

  req.firebaseUser = decodedToken;

  if (dbUser.isRestricted) {
    return res.status(403).json({
      error: 'Your account is currently restricted by campus moderation.',
      code: 'ACCOUNT_RESTRICTED',
    });
  }

  req.currentUser = dbUser;
  next();
};

export const requireVerified = (
  req: AuthRequest,
  res: Response,
  next: NextFunction
) => {
  if (!req.currentUser) {
    return res.status(401).json({ error: 'Authentication required.' });
  }
  if (req.currentUser.verificationStatus !== 'verified') {
    return res.status(403).json({
      error: 'College membership verification is required for this action.',
      code: 'VERIFICATION_REQUIRED',
    });
  }
  next();
};

export const requireRole = (allowedRoles: string[]) => {
  return (req: AuthRequest, res: Response, next: NextFunction) => {
    if (!req.currentUser) {
      return res.status(401).json({ error: 'Authentication required.' });
    }
    if (!allowedRoles.includes(req.currentUser.role)) {
      return res.status(403).json({
        error: 'You do not have permission to perform this action.',
      });
    }
    next();
  };
};
