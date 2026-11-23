import crypto from 'crypto';
import dotenv from 'dotenv';
import express, { NextFunction, Request, Response } from 'express';
import rateLimit from 'express-rate-limit';
import helmet from 'helmet';
import { Storage } from '@google-cloud/storage';
import { unzipSync } from 'fflate';
import multer from 'multer';
import path from 'path';
import { and, asc, desc, eq, gte, inArray, lt, ne, notInArray, or, sql } from 'drizzle-orm';
import { db, pool } from './src/db/index.ts';
import {
  AchievementItem,
  ProjectItem,
  auditLogs,
  blocks,
  colleges,
  comments,
  conversationMembers,
  conversations,
  follows,
  likes,
  messages,
  notifications,
  postAttachments,
  posts,
  reports,
  savedPosts,
  users,
  verificationRequests,
} from './src/db/schema.ts';
import {
  getConfiguredBootstrapAdminEmail,
  validateCollegeDomain,
} from './src/db/users.ts';
import { adminAuth } from './src/lib/firebase-admin.ts';
import {
  AuthRequest,
  optionalAuth,
  requireAuth,
  requireRole,
  requireVerified,
} from './src/middleware/auth.ts';

dotenv.config();

class HttpError extends Error {
  constructor(
    public status: number,
    message: string,
    public code?: string
  ) {
    super(message);
    this.name = 'HttpError';
  }
}

function parsePositiveInt(value: unknown): number | null {
  if (typeof value === 'number') {
    return Number.isInteger(value) && value > 0 ? value : null;
  }
  if (typeof value === 'string' && /^\d+$/.test(value.trim())) {
    const parsed = Number(value.trim());
    return Number.isSafeInteger(parsed) && parsed > 0 ? parsed : null;
  }
  return null;
}

function parseNonNegativeInt(value: unknown): number {
  if (typeof value === 'number') {
    return Number.isInteger(value) && value >= 0 ? value : 0;
  }
  if (typeof value === 'string' && /^\d+$/.test(value.trim())) {
    const parsed = Number(value.trim());
    return Number.isSafeInteger(parsed) && parsed >= 0 ? parsed : 0;
  }
  return 0;
}

function escapeLikePattern(value: string): string {
  return value.replace(/[\\%_]/g, '\\$&');
}

function isPgUniqueViolation(error: unknown, constraintName?: string): boolean {
  const errObj = error as { code?: string; constraint?: string; cause?: { code?: string; constraint?: string } } | null;
  const code = errObj?.code || errObj?.cause?.code;
  const constraint = errObj?.constraint || errObj?.cause?.constraint;
  if (code !== '23505') return false;
  if (constraintName && constraint && constraint !== constraintName) return false;
  return true;
}

const PORT = Number(process.env.PORT) || 3000;
const gcsStorage = new Storage();

function getGcsBucket() {
  const bucketName = (process.env.GCS_BUCKET || '').trim();
  if (!bucketName) {
    throw new HttpError(503, 'Attachment storage is not configured.');
  }
  return gcsStorage.bucket(bucketName);
}

async function deleteGcsObjects(objectKeys: string[]): Promise<void> {
  const uniqueKeys = Array.from(new Set(objectKeys.filter((k) => typeof k === 'string' && k.trim().length > 0)));
  if (uniqueKeys.length === 0) return;
  const bucket = getGcsBucket();
  await Promise.all(
    uniqueKeys.map((key) => bucket.file(key).delete({ ignoreNotFound: true }))
  );
}

function safeHttpUrl(value: unknown, options?: { linkedinOnly?: boolean }): string {
  if (typeof value !== 'string') return '';
  const trimmed = value.trim();
  if (!trimmed || trimmed.length > 250) return '';
  try {
    const parsed = new URL(trimmed);
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
      return '';
    }
    if (options?.linkedinOnly) {
      const host = parsed.hostname.toLowerCase();
      if (host !== 'linkedin.com' && !host.endsWith('.linkedin.com')) {
        return '';
      }
    }
    const normalized = parsed.toString();
    return normalized.length <= 250 ? normalized : '';
  } catch {
    return '';
  }
}

function sanitizeProjects(raw: unknown): ProjectItem[] {
  if (!Array.isArray(raw)) return [];
  const result: ProjectItem[] = [];
  for (const item of raw) {
    if (result.length >= 10) break;
    if (!item || typeof item !== 'object' || Array.isArray(item)) continue;
    const rec = item as Record<string, unknown>;
    const title = typeof rec.title === 'string' ? rec.title.trim().slice(0, 120) : '';
    if (!title) continue;
    const description =
      typeof rec.description === 'string' ? rec.description.trim().slice(0, 600) : '';
    const id =
      typeof rec.id === 'string' && rec.id.trim().length > 0
        ? rec.id.trim().slice(0, 64)
        : crypto.randomUUID().slice(0, 16);
    const link = safeHttpUrl(rec.link);
    const techStack = Array.isArray(rec.techStack)
      ? rec.techStack
          .filter((t): t is string => typeof t === 'string')
          .map((t) => t.trim().slice(0, 30))
          .filter(Boolean)
          .slice(0, 10)
      : [];

    const entry: ProjectItem = { id, title, description };
    if (link) entry.link = link;
    if (techStack.length > 0) entry.techStack = techStack;
    result.push(entry);
  }
  return result;
}

function sanitizeAchievements(raw: unknown): AchievementItem[] {
  if (!Array.isArray(raw)) return [];
  const result: AchievementItem[] = [];
  for (const item of raw) {
    if (result.length >= 15) break;
    if (!item || typeof item !== 'object' || Array.isArray(item)) continue;
    const rec = item as Record<string, unknown>;
    const title = typeof rec.title === 'string' ? rec.title.trim().slice(0, 120) : '';
    if (!title) continue;
    const issuer = typeof rec.issuer === 'string' ? rec.issuer.trim().slice(0, 120) : '';
    const date = typeof rec.date === 'string' ? rec.date.trim().slice(0, 40) : '';
    const description =
      typeof rec.description === 'string' ? rec.description.trim().slice(0, 600) : '';
    const id =
      typeof rec.id === 'string' && rec.id.trim().length > 0
        ? rec.id.trim().slice(0, 64)
        : crypto.randomUUID().slice(0, 16);

    const entry: AchievementItem = { id, title, issuer, date };
    if (description) entry.description = description;
    result.push(entry);
  }
  return result;
}

// Simple in-memory rate limit store (per-user action window)
const rateLimits = new Map<string, { count: number; resetAt: number }>();
const rateLimitCleanupTimer = setInterval(() => {
  const now = Date.now();
  for (const [key, entry] of rateLimits.entries()) {
    if (now > entry.resetAt) {
      rateLimits.delete(key);
    }
  }
}, 5 * 60 * 1000);
rateLimitCleanupTimer.unref();

function checkRateLimit(key: string, maxRequests: number, windowMs: number): boolean {
  const now = Date.now();
  const entry = rateLimits.get(key);
  if (!entry || now > entry.resetAt) {
    rateLimits.set(key, { count: 1, resetAt: now + windowMs });
    return true;
  }
  if (entry.count >= maxRequests) {
    return false;
  }
  entry.count += 1;
  return true;
}

async function insertNotificationIfNotRecent(
  queryDb: Pick<typeof db, 'select' | 'insert'>,
  payload: {
    recipientId: number;
    actorId: number;
    type: string;
    entityId: number;
    message: string;
  }
): Promise<void> {
  const oneHourAgo = new Date(Date.now() - 60 * 60 * 1000);
  const recent = await queryDb
    .select({ id: notifications.id })
    .from(notifications)
    .where(
      and(
        eq(notifications.recipientId, payload.recipientId),
        eq(notifications.actorId, payload.actorId),
        eq(notifications.type, payload.type),
        eq(notifications.entityId, payload.entityId),
        gte(notifications.createdAt, oneHourAgo)
      )
    )
    .limit(1);

  if (recent.length > 0) {
    return;
  }

  await queryDb.insert(notifications).values(payload);
}

const postRateLimit = (req: AuthRequest, res: Response, next: NextFunction) => {
  const me = req.currentUser;
  if (!me) {
    return res.status(401).json({ error: 'Authentication required.' });
  }
  if (!checkRateLimit(`create_post:${me.id}`, 10, 15 * 60 * 1000)) {
    return res.status(429).json({
      error: 'Post rate limit reached. Please wait a few minutes.',
    });
  }
  next();
};

const MAX_ZIP_ENTRIES = 2000;
const MAX_ZIP_UNCOMPRESSED_BYTES = 100 * 1024 * 1024; // 100 MB
const DOCX_MIME = 'application/vnd.openxmlformats-officedocument.wordprocessingml.document';
const PPTX_MIME = 'application/vnd.openxmlformats-officedocument.presentationml.presentation';

function inspectOfficeZip(
  buffer: Buffer
): { mime: string; kind: 'document'; ext: '.docx' | '.pptx' } | null {
  try {
    let entryCount = 0;
    let totalUncompressed = 0;
    let hasContentTypes = false;
    let hasWordDir = false;
    let hasPptDir = false;
    let hasVba = false;

    const bytes = new Uint8Array(buffer.buffer, buffer.byteOffset, buffer.byteLength);
    unzipSync(bytes, {
      filter(file) {
        entryCount += 1;
        if (entryCount > MAX_ZIP_ENTRIES) {
          throw new Error('ZIP entry limit exceeded');
        }
        if (typeof file.originalSize !== 'number' || file.originalSize < 0) {
          throw new Error('Invalid ZIP entry size');
        }
        totalUncompressed += file.originalSize;
        if (totalUncompressed > MAX_ZIP_UNCOMPRESSED_BYTES) {
          throw new Error('ZIP uncompressed size limit exceeded');
        }

        const normalized = file.name.replace(/\\/g, '/').replace(/^\/+/, '');
        const lower = normalized.toLowerCase();

        if (lower === 'vbaproject.bin' || lower.endsWith('/vbaproject.bin')) {
          hasVba = true;
          throw new Error('VBA macros are not allowed');
        }
        if (normalized === '[Content_Types].xml') {
          hasContentTypes = true;
        }
        if (normalized.startsWith('word/')) {
          hasWordDir = true;
        }
        if (normalized.startsWith('ppt/')) {
          hasPptDir = true;
        }

        // Only inspect central-directory headers; skip inflating entries to prevent zip bombs.
        return false;
      },
    });

    if (hasVba || !hasContentTypes) {
      return null;
    }
    if (hasWordDir && !hasPptDir) {
      return { mime: DOCX_MIME, kind: 'document', ext: '.docx' };
    }
    if (hasPptDir && !hasWordDir) {
      return { mime: PPTX_MIME, kind: 'document', ext: '.pptx' };
    }
    return null;
  } catch {
    return null;
  }
}

// Magic-byte file signature validator (never trust filename or browser MIME alone)
function detectFileSignature(buffer: Buffer): { mime: string; kind: 'image' | 'document'; ext: string } | null {
  if (buffer.length < 4) return null;

  // PNG: 89 50 4E 47 0D 0A 1A 0A
  if (
    buffer[0] === 0x89 &&
    buffer[1] === 0x50 &&
    buffer[2] === 0x4e &&
    buffer[3] === 0x47
  ) {
    return { mime: 'image/png', kind: 'image', ext: '.png' };
  }

  // JPEG: FF D8 FF
  if (buffer[0] === 0xff && buffer[1] === 0xd8 && buffer[2] === 0xff) {
    return { mime: 'image/jpeg', kind: 'image', ext: '.jpg' };
  }

  // WEBP: RIFF....WEBP
  if (
    buffer.length >= 12 &&
    buffer.subarray(0, 4).toString('ascii') === 'RIFF' &&
    buffer.subarray(8, 12).toString('ascii') === 'WEBP'
  ) {
    return { mime: 'image/webp', kind: 'image', ext: '.webp' };
  }

  // PDF: %PDF-
  if (buffer.subarray(0, 5).toString('ascii') === '%PDF-') {
    return { mime: 'application/pdf', kind: 'document', ext: '.pdf' };
  }

  // DOCX / PPTX (OpenXML ZIP): PK\x03\x04 — strictly validate archive structure & limits
  if (
    buffer[0] === 0x50 &&
    buffer[1] === 0x4b &&
    buffer[2] === 0x03 &&
    buffer[3] === 0x04
  ) {
    return inspectOfficeZip(buffer);
  }

  return null;
}

function extensionForMime(mimeType: string): string {
  switch (mimeType) {
    case 'image/png':
      return '.png';
    case 'image/jpeg':
      return '.jpg';
    case 'image/webp':
      return '.webp';
    case 'application/pdf':
      return '.pdf';
    case DOCX_MIME:
      return '.docx';
    case PPTX_MIME:
      return '.pptx';
    default:
      return '.bin';
  }
}

function sanitizeAttachmentFilename(originalName: string, detectedExt: string): string {
  const safeExt = detectedExt.startsWith('.') ? detectedExt.toLowerCase() : `.${detectedExt.toLowerCase()}`;
  const cleaned = String(originalName || '')
    .replace(/[\x00-\x1f\x7f]/g, '')
    .replace(/[\\/]/g, '_')
    .replace(/["']/g, '')
    .trim();

  // Strip any user-supplied extension and replace with detected extension
  const lastDot = cleaned.lastIndexOf('.');
  let base = lastDot > 0 ? cleaned.slice(0, lastDot) : cleaned;
  base = base.replace(/^\.+/, '').trim();
  if (!base) {
    base = 'attachment';
  }
  const maxBaseLen = Math.max(1, 120 - safeExt.length);
  return `${base.slice(0, maxBaseLen)}${safeExt}`;
}

function canViewPost(
  viewer: typeof users.$inferSelect | null | undefined,
  post: typeof posts.$inferSelect | null | undefined
): boolean {
  if (!post || post.isHidden) return false;
  if (post.visibility === 'public_preview') return true;
  if (!viewer || viewer.verificationStatus !== 'verified') return false;
  if (viewer.role === 'admin') return true;
  return viewer.collegeId !== null && viewer.collegeId === post.collegeId;
}

async function resolveReportTargetCollegeId(
  queryDb: Pick<typeof db, 'select'>,
  targetType: string,
  targetId: number
): Promise<number | null> {
  if (targetType === 'post') {
    const [p] = await queryDb
      .select({ collegeId: posts.collegeId })
      .from(posts)
      .where(eq(posts.id, targetId))
      .limit(1);
    return p?.collegeId ?? null;
  }
  if (targetType === 'comment') {
    const [row] = await queryDb
      .select({ collegeId: posts.collegeId })
      .from(comments)
      .innerJoin(posts, eq(comments.postId, posts.id))
      .where(eq(comments.id, targetId))
      .limit(1);
    return row?.collegeId ?? null;
  }
  if (targetType === 'user') {
    const [u] = await queryDb
      .select({ collegeId: users.collegeId })
      .from(users)
      .where(eq(users.id, targetId))
      .limit(1);
    return u?.collegeId ?? null;
  }
  if (targetType === 'message') {
    const [row] = await queryDb
      .select({
        convCollegeId: conversations.collegeId,
        senderCollegeId: users.collegeId,
      })
      .from(messages)
      .leftJoin(conversations, eq(messages.conversationId, conversations.id))
      .leftJoin(users, eq(messages.senderId, users.id))
      .where(eq(messages.id, targetId))
      .limit(1);
    return row?.convCollegeId ?? row?.senderCollegeId ?? null;
  }
  return null;
}

const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: 10 * 1024 * 1024, // 10 MB per file
    files: 3,
  },
});

const ALLOWED_CATEGORIES = new Set([
  'study_materials',
  'jobs_internships',
  'student_stories',
  'interview_prep',
  'projects_events',
  'announcements',
]);

function sanitizePublicProfile(
  user: typeof users.$inferSelect,
  viewer?: typeof users.$inferSelect | null
) {
  const isSelf = viewer?.id === user.id;
  const isAdmin = viewer?.role === 'admin';
  const privacy = user.privacySettings || {
    showEmail: false,
    showLinkedIn: true,
    showAcademicYear: true,
    allowMessagesFrom: 'college',
  };

  const isVerifiedSameCollegeViewer =
    Boolean(viewer) &&
    viewer!.verificationStatus === 'verified' &&
    viewer!.collegeId !== null &&
    user.collegeId !== null &&
    viewer!.collegeId === user.collegeId;

  const canViewPrivateEmail =
    isSelf || isAdmin || (privacy.showEmail && isVerifiedSameCollegeViewer);

  return {
    id: user.id,
    displayName: user.displayName,
    headline: user.headline,
    role: user.role,
    verificationStatus: user.verificationStatus,
    collegeId: user.collegeId,
    branch: user.branch,
    academicYear:
      isSelf || isAdmin || privacy.showAcademicYear ? user.academicYear : '',
    bio: user.bio,
    avatarUrl: user.avatarUrl,
    linkedinUrl:
      isSelf || isAdmin || privacy.showLinkedIn ? user.linkedinUrl : '',
    email: canViewPrivateEmail ? user.email : undefined,
    collegeEmail: canViewPrivateEmail ? user.collegeEmail : undefined,
    skills: user.skills,
    projects: user.projects,
    achievements: user.achievements,
    privacySettings: isSelf ? privacy : undefined,
    isRestricted: isAdmin ? user.isRestricted : undefined,
    createdAt: user.createdAt,
  };
}

function sanitizeAuthorForViewer(
  author: typeof users.$inferSelect,
  viewer?: typeof users.$inferSelect | null
) {
  const isSelf = viewer?.id === author.id;
  const isAdmin = viewer?.role === 'admin';
  const isVerifiedSameCollege =
    Boolean(viewer) &&
    viewer!.verificationStatus === 'verified' &&
    viewer!.collegeId !== null &&
    author.collegeId !== null &&
    viewer!.collegeId === author.collegeId;

  if (isSelf || isAdmin || isVerifiedSameCollege) {
    return sanitizePublicProfile(author, viewer);
  }

  return {
    id: author.id,
    displayName: author.displayName,
    avatarUrl: author.avatarUrl,
    role: author.role,
  };
}

async function startServer() {
  const app = express();
  const isProd = process.env.NODE_ENV === 'production';

  app.set('trust proxy', 1);

  app.use(
    helmet({
      crossOriginOpenerPolicy: { policy: 'same-origin-allow-popups' },
      crossOriginEmbedderPolicy: false,
      frameguard: isProd ? { action: 'sameorigin' } : false,
      contentSecurityPolicy: {
        directives: {
          defaultSrc: ["'self'"],
          scriptSrc: isProd
            ? ["'self'", 'https://apis.google.com', 'https://www.gstatic.com']
            : ["'self'", "'unsafe-inline'", 'https://apis.google.com', 'https://www.gstatic.com'],
          styleSrc: ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'],
          fontSrc: ["'self'", 'https://fonts.gstatic.com', 'data:'],
          imgSrc: ["'self'", 'data:', 'blob:', 'https://*.googleusercontent.com'],
          connectSrc: isProd
            ? [
                "'self'",
                'https://*.googleapis.com',
                'https://identitytoolkit.googleapis.com',
                'https://securetoken.googleapis.com',
                'https://*.firebaseapp.com',
                'https://apis.google.com',
              ]
            : [
                "'self'",
                'ws:',
                'wss:',
                'https://*.googleapis.com',
                'https://identitytoolkit.googleapis.com',
                'https://securetoken.googleapis.com',
                'https://*.firebaseapp.com',
                'https://apis.google.com',
              ],
          frameSrc: ["'self'", 'https://*.firebaseapp.com', 'https://accounts.google.com'],
          objectSrc: ["'none'"],
          baseUri: ["'self'"],
          ...(isProd ? { frameAncestors: ["'self'"] } : { frameAncestors: null }),
        },
      },
    })
  );

  app.use(express.json({ limit: '2mb' }));

  app.get('/api/health', (_req, res) => {
    res.json({ status: 'ok' });
  });

  app.get('/api/health/ready', async (_req, res) => {
    try {
      await db.execute(sql`SELECT 1`);
      res.json({ status: 'ready' });
    } catch (error) {
      console.error('Readiness probe failed:', error);
      res.status(503).json({ status: 'unavailable' });
    }
  });

  app.get('/api/config', (_req, res) => {
    res.json({ uploadsEnabled: Boolean((process.env.GCS_BUCKET || '').trim()) });
  });

  const apiGlobalLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 3000,
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: 'Too many requests. Please try again later.' },
  });
  app.use('/api', apiGlobalLimiter);

  app.get('/api/colleges', async (_req, res) => {
    try {
      const list = await db
        .select()
        .from(colleges)
        .where(eq(colleges.status, 'active'))
        .orderBy(colleges.id);
      res.json(list);
    } catch (error) {
      console.error('Error loading colleges:', error);
      res.status(500).json({ error: 'Unable to load colleges.' });
    }
  });

  // Current user profile + counts
  app.get('/api/me', requireAuth, async (req: AuthRequest, res: Response) => {
    try {
      const me = req.currentUser!;
      const [college] = me.collegeId
        ? await db.select().from(colleges).where(eq(colleges.id, me.collegeId)).limit(1)
        : [];

      const unreadNotifs = await db
        .select({ count: sql<number>`count(*)::int` })
        .from(notifications)
        .where(and(eq(notifications.recipientId, me.id), eq(notifications.isRead, false)));

      const followerRows = await db
        .select({ count: sql<number>`count(*)::int` })
        .from(follows)
        .where(eq(follows.followingId, me.id));

      const followingRows = await db
        .select({ count: sql<number>`count(*)::int` })
        .from(follows)
        .where(eq(follows.followerId, me.id));

      res.json({
        user: sanitizePublicProfile(me, me),
        college: college ?? null,
        unreadNotifications: unreadNotifs[0]?.count ?? 0,
        followersCount: followerRows[0]?.count ?? 0,
        followingCount: followingRows[0]?.count ?? 0,
      });
    } catch (error) {
      console.error('Error fetching /api/me:', error);
      res.status(500).json({ error: 'Unable to fetch your profile.' });
    }
  });

  app.patch('/api/me', requireAuth, async (req: AuthRequest, res: Response) => {
    try {
      const me = req.currentUser!;
      const body = req.body || {};

      const displayName =
        typeof body.displayName === 'string' && body.displayName.trim().length >= 2
          ? body.displayName.trim().slice(0, 80)
          : me.displayName;
      const headline =
        typeof body.headline === 'string'
          ? body.headline.trim().slice(0, 140)
          : me.headline;
      const branch =
        typeof body.branch === 'string' ? body.branch.trim().slice(0, 80) : me.branch;
      const academicYear =
        typeof body.academicYear === 'string'
          ? body.academicYear.trim().slice(0, 60)
          : me.academicYear;
      const bio =
        typeof body.bio === 'string' ? body.bio.trim().slice(0, 800) : me.bio;
      const linkedinUrl =
        typeof body.linkedinUrl === 'string'
          ? safeHttpUrl(body.linkedinUrl, { linkedinOnly: true })
          : me.linkedinUrl;
      const skills = Array.isArray(body.skills)
        ? body.skills
            .filter((s: unknown): s is string => typeof s === 'string')
            .map((s: string) => s.trim().slice(0, 40))
            .filter(Boolean)
            .slice(0, 20)
        : me.skills;
      const projects = Array.isArray(body.projects)
        ? sanitizeProjects(body.projects)
        : me.projects;
      const achievements = Array.isArray(body.achievements)
        ? sanitizeAchievements(body.achievements)
        : me.achievements;
      const privacySettings =
        body.privacySettings && typeof body.privacySettings === 'object'
          ? {
              showEmail: Boolean(body.privacySettings.showEmail),
              showLinkedIn: Boolean(body.privacySettings.showLinkedIn),
              showAcademicYear: Boolean(body.privacySettings.showAcademicYear),
              allowMessagesFrom:
                body.privacySettings.allowMessagesFrom === 'followers'
                  ? ('followers' as const)
                  : ('college' as const),
            }
          : me.privacySettings;

      let avatarUrl = me.avatarUrl;
      if (body.avatarUrl !== undefined) {
        if (typeof body.avatarUrl !== 'string') {
          return res.status(400).json({ error: 'Invalid profile photo format.' });
        }
        const avatarDataUrlRegex = /^data:image\/(webp|jpeg|png);base64,[A-Za-z0-9+/=]+$/;
        if (
          body.avatarUrl !== '' &&
          (body.avatarUrl.length > 24000 || !avatarDataUrlRegex.test(body.avatarUrl))
        ) {
          return res.status(400).json({
            error: 'Profile photo must be a JPG, PNG, or WEBP data URL under 24,000 characters.',
          });
        }
        avatarUrl = body.avatarUrl;
      }

      const [updated] = await db
        .update(users)
        .set({
          displayName,
          headline,
          branch,
          academicYear,
          bio,
          avatarUrl,
          linkedinUrl,
          skills,
          projects,
          achievements,
          privacySettings,
          updatedAt: new Date(),
        })
        .where(eq(users.id, me.id))
        .returning();

      res.json({ user: sanitizePublicProfile(updated, updated) });
    } catch (error) {
      console.error('Error updating profile:', error);
      res.status(500).json({ error: 'Unable to update profile.' });
    }
  });

  app.delete('/api/me', requireAuth, async (req: AuthRequest, res: Response) => {
    try {
      const me = req.currentUser!;

      // Collect all GCS attachment objects belonging to this user's posts before deleting DB rows
      const userPostRows = await db
        .select({ id: posts.id })
        .from(posts)
        .where(eq(posts.authorId, me.id));
      const userPostIds = userPostRows.map((p) => p.id);

      const attRows =
        userPostIds.length > 0
          ? await db
              .select({ storedName: postAttachments.storedName })
              .from(postAttachments)
              .where(
                or(
                  eq(postAttachments.uploaderId, me.id),
                  inArray(postAttachments.postId, userPostIds)
                )
              )
          : await db
              .select({ storedName: postAttachments.storedName })
              .from(postAttachments)
              .where(eq(postAttachments.uploaderId, me.id));

      const objectKeys = attRows.map((a) => a.storedName);

      // Delete DB user FIRST so cascading deletes succeed atomically before external cleanup
      await db.delete(users).where(eq(users.id, me.id));

      if (objectKeys.length > 0) {
        try {
          await deleteGcsObjects(objectKeys);
        } catch (gcsErr) {
          console.error('Error deleting GCS objects after account DB delete:', gcsErr);
        }
      }

      try {
        await adminAuth.deleteUser(me.uid);
      } catch (authErr: unknown) {
        const code = (authErr as { code?: string } | null)?.code;
        if (code !== 'auth/user-not-found') {
          console.error('Error deleting Firebase Auth user after DB delete:', authErr);
        }
      }

      res.json({ deleted: true });
    } catch (error) {
      if (error instanceof HttpError) {
        return res
          .status(error.status)
          .json({ error: error.message, ...(error.code ? { code: error.code } : {}) });
      }
      console.error('Error deleting account:', error);
      res.status(500).json({ error: 'Unable to delete account.' });
    }
  });

  // Verification workflow
  app.get('/api/verification/status', requireAuth, async (req: AuthRequest, res: Response) => {
    try {
      const me = req.currentUser!;
      const latest = await db
        .select({
          id: verificationRequests.id,
          userId: verificationRequests.userId,
          collegeId: verificationRequests.collegeId,
          requestedRole: verificationRequests.requestedRole,
          collegeEmail: verificationRequests.collegeEmail,
          method: verificationRequests.method,
          evidenceNote: verificationRequests.evidenceNote,
          status: verificationRequests.status,
          reviewNotes: verificationRequests.reviewNotes,
          createdAt: verificationRequests.createdAt,
          reviewedAt: verificationRequests.reviewedAt,
        })
        .from(verificationRequests)
        .where(eq(verificationRequests.userId, me.id))
        .orderBy(desc(verificationRequests.createdAt))
        .limit(1);

      const latestSafe = latest[0]
        ? {
            ...latest[0],
            evidenceNote:
              latest[0].status === 'pending'
                ? latest[0].evidenceNote
                : '[Redacted after decision]',
          }
        : null;

      res.json({
        verificationStatus: me.verificationStatus,
        latestRequest: latestSafe,
      });
    } catch (error) {
      console.error('Error loading verification status:', error);
      res.status(500).json({ error: 'Unable to load verification status.' });
    }
  });

  app.post('/api/verification/email-code', requireAuth, async (_req: AuthRequest, res: Response) => {
    return res.status(503).json({
      error:
        'Self-service email OTP verification is temporarily disabled while transactional email delivery is being configured. Please use Admin Review or verify your institutional email via Firebase.',
      code: 'EMAIL_OTP_DISABLED',
    });
  });

  app.post('/api/verification/confirm-code', requireAuth, async (_req: AuthRequest, res: Response) => {
    return res.status(503).json({
      error:
        'Self-service email OTP verification is temporarily disabled while transactional email delivery is being configured. Please use Admin Review or verify your institutional email via Firebase.',
      code: 'EMAIL_OTP_DISABLED',
    });
  });

  app.post('/api/verification/request', requireAuth, async (req: AuthRequest, res: Response) => {
    try {
      const me = req.currentUser!;
      if (!checkRateLimit(`verification_req:${me.id}`, 3, 24 * 60 * 60 * 1000)) {
        return res.status(429).json({
          error: 'Daily verification request limit reached. Please try again tomorrow.',
        });
      }
      const { collegeId, requestedRole, collegeEmail, evidenceNote } = req.body || {};
      if (typeof evidenceNote !== 'string' || evidenceNote.trim().length < 10) {
        return res.status(400).json({
          error:
            'Please provide enrollment details (student ID number, department, or faculty directory reference).',
        });
      }

      const targetCollegeId = parsePositiveInt(collegeId ?? me.collegeId);
      if (!targetCollegeId) {
        return res.status(400).json({ error: 'Please select a valid college.' });
      }

      const safeRole =
        requestedRole === 'faculty' || requestedRole === 'alumni' ? requestedRole : 'student';
      const safeCollegeEmail =
        typeof collegeEmail === 'string' ? collegeEmail.trim().toLowerCase().slice(0, 120) : '';
      if (safeCollegeEmail && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(safeCollegeEmail)) {
        return res.status(400).json({ error: 'Enter a valid optional college email address.' });
      }

      const created = await db.transaction(async (tx) => {
        const [freshUser] = await tx
          .select()
          .from(users)
          .where(eq(users.id, me.id))
          .limit(1);
        if (!freshUser) {
          throw new HttpError(404, 'Account not found.');
        }
        if (freshUser.verificationStatus === 'verified') {
          throw new HttpError(400, 'Your account is already verified.');
        }

        const [targetCollege] = await tx
          .select()
          .from(colleges)
          .where(and(eq(colleges.id, targetCollegeId), eq(colleges.status, 'active')))
          .limit(1);
        if (!targetCollege) {
          throw new HttpError(400, 'Selected college does not exist or is currently inactive.');
        }

        const existingPending = await tx
          .select({ id: verificationRequests.id })
          .from(verificationRequests)
          .where(
            and(
              eq(verificationRequests.userId, me.id),
              eq(verificationRequests.status, 'pending')
            )
          )
          .limit(1);
        if (existingPending.length > 0) {
          throw new HttpError(
            409,
            'You already have a pending verification request awaiting admin review.',
            'PENDING_REQUEST_EXISTS'
          );
        }

        const [inserted] = await tx
          .insert(verificationRequests)
          .values({
            userId: me.id,
            collegeId: targetCollege.id,
            requestedRole: safeRole,
            collegeEmail: safeCollegeEmail,
            verificationCode: '',
            method: 'admin_review',
            evidenceNote: evidenceNote.trim().slice(0, 600),
            status: 'pending',
          })
          .returning({
            id: verificationRequests.id,
            userId: verificationRequests.userId,
            collegeId: verificationRequests.collegeId,
            requestedRole: verificationRequests.requestedRole,
            collegeEmail: verificationRequests.collegeEmail,
            method: verificationRequests.method,
            evidenceNote: verificationRequests.evidenceNote,
            status: verificationRequests.status,
            reviewNotes: verificationRequests.reviewNotes,
            createdAt: verificationRequests.createdAt,
            reviewedAt: verificationRequests.reviewedAt,
          });

        // Do NOT assign users.collegeId until an administrator approves the request.
        await tx
          .update(users)
          .set({
            verificationStatus: 'pending',
            updatedAt: new Date(),
          })
          .where(eq(users.id, me.id));

        return inserted;
      });

      res.status(201).json({ request: created });
    } catch (error) {
      if (error instanceof HttpError) {
        return res
          .status(error.status)
          .json({ error: error.message, ...(error.code ? { code: error.code } : {}) });
      }
      if (isPgUniqueViolation(error, 'verification_requests_one_pending_per_user_idx')) {
        return res.status(409).json({
          error: 'You already have a pending verification request awaiting admin review.',
          code: 'PENDING_REQUEST_EXISTS',
        });
      }
      console.error('Error submitting verification request:', error);
      res.status(500).json({ error: 'Unable to submit verification request.' });
    }
  });

  // Feed & Posts
  app.get('/api/feed', optionalAuth, async (req: AuthRequest, res: Response) => {
    try {
      const viewer = req.currentUser;
      const isVerifiedMember = viewer?.verificationStatus === 'verified';
      const category = typeof req.query.category === 'string' ? req.query.category : '';
      const q = typeof req.query.q === 'string' ? req.query.q.trim() : '';
      const authorIdParam = parsePositiveInt(req.query.authorId);
      const savedOnly = req.query.savedOnly === 'true';
      const followingOnly = req.query.followingOnly === 'true';
      const limit = Math.min(Math.max(Number(req.query.limit) || 12, 1), 30);
      const offset = Math.max(Number(req.query.offset) || 0, 0);

      // Determine blocked & followed users for viewer
      let blockedUserIds: number[] = [];
      let followingIds: number[] = [];
      let savedIds: number[] = [];
      let likedIds: number[] = [];

      if (viewer) {
        const blockedRows = await db
          .select({ blockedId: blocks.blockedId })
          .from(blocks)
          .where(eq(blocks.blockerId, viewer.id));
        const blockedByRows = await db
          .select({ blockerId: blocks.blockerId })
          .from(blocks)
          .where(eq(blocks.blockedId, viewer.id));
        blockedUserIds = Array.from(
          new Set([
            ...blockedRows.map((b) => b.blockedId),
            ...blockedByRows.map((b) => b.blockerId),
          ])
        );

        const followRows = await db
          .select({ followingId: follows.followingId })
          .from(follows)
          .where(eq(follows.followerId, viewer.id));
        followingIds = followRows.map((f) => f.followingId);

        const savedRows = await db
          .select({ postId: savedPosts.postId })
          .from(savedPosts)
          .where(eq(savedPosts.userId, viewer.id));
        savedIds = savedRows.map((s) => s.postId);

        const likeRows = await db
          .select({ postId: likes.postId })
          .from(likes)
          .where(eq(likes.userId, viewer.id));
        likedIds = likeRows.map((l) => l.postId);
      }

      if (savedOnly && (!viewer || savedIds.length === 0)) {
        return res.json({ items: [], hasMore: false, restrictedMode: !isVerifiedMember });
      }
      if (followingOnly && (!viewer || followingIds.length === 0)) {
        return res.json({ items: [], hasMore: false, restrictedMode: !isVerifiedMember });
      }

      const conditions: any[] = [eq(posts.isHidden, false)];

      // Strict membership boundary (fail closed if collegeId is missing for non-admin)
      if (!isVerifiedMember) {
        conditions.push(eq(posts.visibility, 'public_preview'));
      } else if (viewer && viewer.role !== 'admin') {
        if (viewer.collegeId !== null) {
          conditions.push(eq(posts.collegeId, viewer.collegeId));
        } else {
          conditions.push(eq(posts.visibility, 'public_preview'));
        }
      }

      if (blockedUserIds.length > 0) {
        conditions.push(notInArray(posts.authorId, blockedUserIds));
      }

      if (category && ALLOWED_CATEGORIES.has(category)) {
        conditions.push(eq(posts.category, category));
      }

      if (authorIdParam) {
        conditions.push(eq(posts.authorId, authorIdParam));
      }

      if (savedOnly && savedIds.length > 0) {
        conditions.push(inArray(posts.id, savedIds));
      }

      if (followingOnly && followingIds.length > 0) {
        conditions.push(inArray(posts.authorId, followingIds));
      }

      if (q) {
        const pattern = `%${escapeLikePattern(q)}%`;
        conditions.push(
          or(
            sql`${posts.title} ILIKE ${pattern} ESCAPE '\\'`,
            sql`${posts.content} ILIKE ${pattern} ESCAPE '\\'`,
            sql`${posts.contextLabel} ILIKE ${pattern} ESCAPE '\\'`,
            sql`array_to_string(${posts.tags}, ' ') ILIKE ${pattern} ESCAPE '\\'`
          )
        );
      }

      const rawPosts = await db
        .select()
        .from(posts)
        .where(and(...conditions))
        .orderBy(desc(posts.createdAt))
        .limit(limit + 1)
        .offset(offset);

      const hasMore = rawPosts.length > limit;
      const pagePosts = rawPosts.slice(0, limit);

      if (pagePosts.length === 0) {
        return res.json({
          items: [],
          hasMore: false,
          restrictedMode: !isVerifiedMember,
        });
      }

      const authorIds = Array.from(new Set(pagePosts.map((p) => p.authorId)));
      const authorRows = await db
        .select()
        .from(users)
        .where(inArray(users.id, authorIds));
      const authorMap = new Map(authorRows.map((u) => [u.id, u]));

      const postIds = pagePosts.map((p) => p.id);
      const attachmentRows = await db
        .select()
        .from(postAttachments)
        .where(inArray(postAttachments.postId, postIds));

      const attachmentsByPost = new Map<number, typeof attachmentRows>();
      for (const att of attachmentRows) {
        const list = attachmentsByPost.get(att.postId) || [];
        list.push(att);
        attachmentsByPost.set(att.postId, list);
      }

      const items = pagePosts.map((post) => {
        const author = authorMap.get(post.authorId);
        return {
          ...post,
          author: author ? sanitizeAuthorForViewer(author, viewer) : null,
          attachments: (attachmentsByPost.get(post.id) || []).map((a) => ({
            id: a.id,
            originalName: a.originalName,
            mimeType: a.mimeType,
            sizeBytes: a.sizeBytes,
            kind: a.kind,
          })),
          isLiked: likedIds.includes(post.id),
          isSaved: savedIds.includes(post.id),
          isFollowingAuthor: followingIds.includes(post.authorId),
        };
      });

      res.json({
        items,
        hasMore,
        restrictedMode: !isVerifiedMember,
      });
    } catch (error) {
      console.error('Error loading feed:', error);
      res.status(500).json({ error: 'Unable to load campus feed.' });
    }
  });

  app.post(
    '/api/posts',
    requireAuth,
    requireVerified,
    postRateLimit,
    upload.array('attachments', 3),
    async (req: AuthRequest, res: Response) => {
      try {
        const me = req.currentUser!;

        const title = typeof req.body.title === 'string' ? req.body.title.trim() : '';
        const content = typeof req.body.content === 'string' ? req.body.content.trim() : '';
        const category = typeof req.body.category === 'string' ? req.body.category.trim() : '';
        const contextLabel =
          typeof req.body.contextLabel === 'string' ? req.body.contextLabel.trim().slice(0, 100) : '';
        const externalLink = safeHttpUrl(req.body.externalLink);
        const visibility =
          req.body.visibility === 'public_preview' ? 'public_preview' : 'college';

        if (title.length < 3 || title.length > 160) {
          return res.status(400).json({ error: 'Title must be between 3 and 160 characters.' });
        }
        if (content.length < 10 || content.length > 8000) {
          return res.status(400).json({ error: 'Post content must be between 10 and 8,000 characters.' });
        }
        if (!ALLOWED_CATEGORIES.has(category)) {
          return res.status(400).json({ error: 'Select a valid post category.' });
        }

        let tags: string[] = [];
        if (typeof req.body.tags === 'string') {
          tags = req.body.tags
            .split(',')
            .map((t: string) => t.trim().toLowerCase().replace(/^#/, '').slice(0, 30))
            .filter(Boolean)
            .slice(0, 8);
        }

        // Validate uploaded files strictly via magic-byte & OpenXML archive inspection
        const files = (req.files as Express.Multer.File[]) || [];
        if (files.length > 0 && !(process.env.GCS_BUCKET || '').trim()) {
          return res.status(400).json({ error: 'File uploads are not enabled yet.' });
        }
        const validatedFiles: Array<{
          file: Express.Multer.File;
          detected: { mime: string; kind: 'image' | 'document'; ext: string };
          safeOriginalName: string;
        }> = [];

        for (const file of files) {
          const detected = detectFileSignature(file.buffer);
          if (!detected) {
            return res.status(400).json({
              error: `Unsupported or invalid file content for "${file.originalname}". Only verified PNG, JPEG, WEBP, PDF, DOCX, and PPTX files up to 10 MB are permitted.`,
            });
          }
          validatedFiles.push({
            file,
            detected,
            safeOriginalName: sanitizeAttachmentFilename(file.originalname, detected.ext),
          });
        }

        let targetCollegeId: number | null = null;
        if (me.role === 'admin') {
          targetCollegeId = parsePositiveInt(req.body.collegeId);
          if (!targetCollegeId) {
            return res.status(400).json({
              error: 'Administrators must explicitly select an active college for this post.',
            });
          }
        } else {
          targetCollegeId = me.collegeId;
          if (!targetCollegeId) {
            return res.status(403).json({
              error: 'Your account must be assigned to an active college before posting.',
            });
          }
        }

        const [activeCollege] = await db
          .select({ id: colleges.id })
          .from(colleges)
          .where(and(eq(colleges.id, targetCollegeId), eq(colleges.status, 'active')))
          .limit(1);

        if (!activeCollege) {
          return res.status(400).json({
            error: 'Selected college does not exist or is currently inactive.',
          });
        }

        const collegeId = activeCollege.id;
        const bucket = validatedFiles.length > 0 ? getGcsBucket() : null;

        // Upload validated files to GCS FIRST (outside any DB transaction)
        const uploadedFiles: Array<{
          storedName: string;
          originalName: string;
          mimeType: string;
          sizeBytes: number;
          kind: 'image' | 'document';
        }> = [];

        try {
          for (const { file, detected, safeOriginalName } of validatedFiles) {
            const storedName = `${crypto.randomUUID()}${detected.ext}`;
            await bucket!.file(storedName).save(file.buffer, {
              resumable: false,
              contentType: detected.mime,
              metadata: {
                cacheControl: 'private, no-store',
              },
            });
            uploadedFiles.push({
              storedName,
              originalName: safeOriginalName,
              mimeType: detected.mime,
              sizeBytes: file.size,
              kind: detected.kind,
            });
          }
        } catch (uploadErr) {
          if (uploadedFiles.length > 0) {
            await deleteGcsObjects(uploadedFiles.map((f) => f.storedName)).catch((cleanupErr) => {
              console.error('Failed to clean up partial GCS uploads:', cleanupErr);
            });
          }
          throw uploadErr;
        }

        let createdPost: typeof posts.$inferSelect;
        let attachmentMeta: Array<{
          id: number;
          originalName: string;
          mimeType: string;
          sizeBytes: number;
          kind: string;
        }> = [];

        try {
          const txResult = await db.transaction(async (tx) => {
            const [postRow] = await tx
              .insert(posts)
              .values({
                authorId: me.id,
                collegeId,
                category,
                title,
                content,
                tags,
                contextLabel,
                externalLink,
                visibility,
              })
              .returning();

            const savedAttachments: Array<{
              id: number;
              originalName: string;
              mimeType: string;
              sizeBytes: number;
              kind: string;
            }> = [];

            if (uploadedFiles.length > 0) {
              const insertedAtts = await tx
                .insert(postAttachments)
                .values(
                  uploadedFiles.map((f) => ({
                    postId: postRow.id,
                    uploaderId: me.id,
                    originalName: f.originalName,
                    storedName: f.storedName,
                    mimeType: f.mimeType,
                    sizeBytes: f.sizeBytes,
                    kind: f.kind,
                  }))
                )
                .returning();

              for (const savedAtt of insertedAtts) {
                savedAttachments.push({
                  id: savedAtt.id,
                  originalName: savedAtt.originalName,
                  mimeType: savedAtt.mimeType,
                  sizeBytes: savedAtt.sizeBytes,
                  kind: savedAtt.kind,
                });
              }
            }

            return { postRow, savedAttachments };
          });

          createdPost = txResult.postRow;
          attachmentMeta = txResult.savedAttachments;
        } catch (txError) {
          if (uploadedFiles.length > 0) {
            await deleteGcsObjects(uploadedFiles.map((f) => f.storedName)).catch((cleanupErr) => {
              console.error('Failed to clean up GCS objects after DB transaction failure:', cleanupErr);
            });
          }
          throw txError;
        }

        res.status(201).json({
          post: {
            ...createdPost,
            author: sanitizePublicProfile(me, me),
            attachments: attachmentMeta,
            isLiked: false,
            isSaved: false,
            isFollowingAuthor: false,
          },
        });
      } catch (error) {
        if (error instanceof HttpError) {
          return res
            .status(error.status)
            .json({ error: error.message, ...(error.code ? { code: error.code } : {}) });
        }
        console.error('Error creating post:', error);
        res.status(500).json({ error: 'Unable to publish post.' });
      }
    }
  );

  app.patch('/api/posts/:id', requireAuth, requireVerified, async (req: AuthRequest, res: Response) => {
    try {
      const me = req.currentUser!;
      const postId = parsePositiveInt(req.params.id);
      if (!postId) {
        return res.status(400).json({ error: 'Invalid post ID.' });
      }
      const [existing] = await db.select().from(posts).where(eq(posts.id, postId)).limit(1);
      if (!existing) {
        return res.status(404).json({ error: 'Post not found.' });
      }
      if (existing.authorId !== me.id && me.role !== 'admin') {
        return res.status(403).json({ error: 'You can only edit your own posts.' });
      }

      const body = req.body || {};
      const title =
        typeof body.title === 'string' && body.title.trim().length >= 3
          ? body.title.trim().slice(0, 160)
          : existing.title;
      const content =
        typeof body.content === 'string' && body.content.trim().length >= 10
          ? body.content.trim().slice(0, 8000)
          : existing.content;
      const category =
        typeof body.category === 'string' && ALLOWED_CATEGORIES.has(body.category)
          ? body.category
          : existing.category;
      const contextLabel =
        typeof body.contextLabel === 'string'
          ? body.contextLabel.trim().slice(0, 100)
          : existing.contextLabel;
      const externalLink =
        body.externalLink !== undefined ? safeHttpUrl(body.externalLink) : existing.externalLink;

      const [updated] = await db
        .update(posts)
        .set({ title, content, category, contextLabel, externalLink, updatedAt: new Date() })
        .where(eq(posts.id, postId))
        .returning();

      res.json({ post: updated });
    } catch (error) {
      console.error('Error editing post:', error);
      res.status(500).json({ error: 'Unable to update post.' });
    }
  });

  app.delete('/api/posts/:id', requireAuth, async (req: AuthRequest, res: Response) => {
    try {
      const me = req.currentUser!;
      const postId = parsePositiveInt(req.params.id);
      if (!postId) {
        return res.status(400).json({ error: 'Invalid post ID.' });
      }
      const [existing] = await db.select().from(posts).where(eq(posts.id, postId)).limit(1);
      if (!existing) {
        return res.status(404).json({ error: 'Post not found.' });
      }

      const isOwner = existing.authorId === me.id;
      const isAdmin = me.role === 'admin';
      const isSameCollegeMod =
        me.role === 'moderator' && me.collegeId !== null && existing.collegeId === me.collegeId;

      if (!isOwner && !isAdmin && !isSameCollegeMod) {
        return res.status(403).json({ error: 'You do not have permission to delete this post.' });
      }

      const atts = await db
        .select({ storedName: postAttachments.storedName })
        .from(postAttachments)
        .where(eq(postAttachments.postId, postId));
      const objectKeys = atts.map((a) => a.storedName);

      await db.transaction(async (tx) => {
        await tx.delete(posts).where(eq(posts.id, postId));
        if ((isAdmin || isSameCollegeMod) && !isOwner) {
          await tx.insert(auditLogs).values({
            actorId: me.id,
            action: 'POST_DELETED_BY_MODERATOR',
            targetType: 'post',
            targetId: postId,
            reason: 'Removed during moderation review',
          });
        }
      });

      // Delete objects from GCS only AFTER the DB delete succeeds
      if (objectKeys.length > 0) {
        await deleteGcsObjects(objectKeys).catch((cleanupErr) => {
          console.error('Failed to delete GCS post objects after DB delete:', cleanupErr);
        });
      }

      res.json({ deleted: true });
    } catch (error) {
      console.error('Error deleting post:', error);
      res.status(500).json({ error: 'Unable to delete post.' });
    }
  });

  // Protected private attachment access
  app.get('/api/attachments/:id', requireAuth, requireVerified, async (req: AuthRequest, res: Response) => {
    try {
      const me = req.currentUser!;
      const attId = parsePositiveInt(req.params.id);
      if (!attId) {
        return res.status(400).json({ error: 'Invalid attachment ID.' });
      }
      const [att] = await db
        .select()
        .from(postAttachments)
        .where(eq(postAttachments.id, attId))
        .limit(1);

      if (!att) {
        return res.status(404).json({ error: 'Attachment not found.' });
      }

      const [parentPost] = await db
        .select()
        .from(posts)
        .where(eq(posts.id, att.postId))
        .limit(1);

      if (!canViewPost(me, parentPost)) {
        return res.status(404).json({ error: 'Attachment not found.' });
      }

      const file = getGcsBucket().file(att.storedName);
      const [exists] = await file.exists();
      if (!exists) {
        return res.status(404).json({ error: 'Stored file missing.' });
      }

      const disposition = att.kind === 'image' ? 'inline' : 'attachment';
      const safeName = sanitizeAttachmentFilename(att.originalName, extensionForMime(att.mimeType));

      res.setHeader('Content-Type', att.mimeType);
      res.setHeader('X-Content-Type-Options', 'nosniff');
      res.setHeader(
        'Content-Disposition',
        `${disposition}; filename="file"; filename*=UTF-8''${encodeURIComponent(safeName)}`
      );

      const readStream = file.createReadStream();
      readStream.on('error', (streamErr) => {
        console.error('Error streaming attachment from GCS:', streamErr);
        if (!res.headersSent) {
          res.status(500).json({ error: 'Unable to download attachment.' });
        } else {
          res.destroy(streamErr);
        }
      });
      readStream.pipe(res);
    } catch (error) {
      if (error instanceof HttpError) {
        return res
          .status(error.status)
          .json({ error: error.message, ...(error.code ? { code: error.code } : {}) });
      }
      console.error('Error streaming attachment:', error);
      res.status(500).json({ error: 'Unable to download attachment.' });
    }
  });

  // Like / Save / Comments
  app.post('/api/posts/:id/like', requireAuth, requireVerified, async (req: AuthRequest, res: Response) => {
    try {
      const me = req.currentUser!;
      if (!checkRateLimit(`like:${me.id}`, 60, 10 * 60 * 1000)) {
        return res.status(429).json({ error: 'Too many reactions. Please pause briefly.' });
      }
      const postId = parsePositiveInt(req.params.id);
      if (!postId) {
        return res.status(400).json({ error: 'Invalid post ID.' });
      }
      const [post] = await db.select().from(posts).where(eq(posts.id, postId)).limit(1);
      if (!canViewPost(me, post)) {
        return res.status(404).json({ error: 'Post not found.' });
      }

      const result = await db.transaction(async (tx) => {
        const existing = await tx
          .select({ id: likes.id })
          .from(likes)
          .where(and(eq(likes.postId, postId), eq(likes.userId, me.id)))
          .limit(1);

        if (existing.length > 0) {
          const deleted = await tx
            .delete(likes)
            .where(and(eq(likes.postId, postId), eq(likes.userId, me.id)))
            .returning({ id: likes.id });

          if (deleted.length > 0) {
            const [updated] = await tx
              .update(posts)
              .set({ likesCount: sql`GREATEST(0, ${posts.likesCount} - 1)` })
              .where(eq(posts.id, postId))
              .returning({ likesCount: posts.likesCount });
            return { liked: false, likesCount: updated?.likesCount ?? 0 };
          }

          const [currentPost] = await tx
            .select({ likesCount: posts.likesCount })
            .from(posts)
            .where(eq(posts.id, postId))
            .limit(1);
          return { liked: false, likesCount: currentPost?.likesCount ?? 0 };
        }

        const inserted = await tx
          .insert(likes)
          .values({ postId, userId: me.id })
          .onConflictDoNothing()
          .returning({ id: likes.id });

        if (inserted.length === 0) {
          const [currentPost] = await tx
            .select({ likesCount: posts.likesCount })
            .from(posts)
            .where(eq(posts.id, postId))
            .limit(1);
          return { liked: true, likesCount: currentPost?.likesCount ?? post.likesCount };
        }

        const [updated] = await tx
          .update(posts)
          .set({ likesCount: sql`${posts.likesCount} + 1` })
          .where(eq(posts.id, postId))
          .returning({ likesCount: posts.likesCount });

        if (post.authorId !== me.id) {
          await insertNotificationIfNotRecent(tx, {
            recipientId: post.authorId,
            actorId: me.id,
            type: 'like',
            entityId: postId,
            message: `${me.displayName} appreciated your post "${post.title.slice(0, 60)}"`,
          });
        }

        return { liked: true, likesCount: updated?.likesCount ?? post.likesCount + 1 };
      });

      return res.json(result);
    } catch (error) {
      if (isPgUniqueViolation(error)) {
        const postId = parsePositiveInt(req.params.id);
        const [currentPost] = postId
          ? await db
              .select({ likesCount: posts.likesCount })
              .from(posts)
              .where(eq(posts.id, postId))
              .limit(1)
          : [];
        return res.json({ liked: true, likesCount: currentPost?.likesCount ?? 0 });
      }
      console.error('Error toggling like:', error);
      res.status(500).json({ error: 'Unable to update reaction.' });
    }
  });

  app.post('/api/posts/:id/save', requireAuth, requireVerified, async (req: AuthRequest, res: Response) => {
    try {
      const me = req.currentUser!;
      if (!checkRateLimit(`save:${me.id}`, 60, 10 * 60 * 1000)) {
        return res.status(429).json({ error: 'Too many save actions. Please pause briefly.' });
      }
      const postId = parsePositiveInt(req.params.id);
      if (!postId) {
        return res.status(400).json({ error: 'Invalid post ID.' });
      }
      const [post] = await db.select().from(posts).where(eq(posts.id, postId)).limit(1);
      if (!canViewPost(me, post)) {
        return res.status(404).json({ error: 'Post not found.' });
      }

      const existing = await db
        .select()
        .from(savedPosts)
        .where(and(eq(savedPosts.postId, postId), eq(savedPosts.userId, me.id)))
        .limit(1);

      if (existing.length > 0) {
        await db.delete(savedPosts).where(eq(savedPosts.id, existing[0].id));
        return res.json({ saved: false });
      }
      await db.insert(savedPosts).values({ postId, userId: me.id });
      return res.json({ saved: true });
    } catch (error) {
      if (isPgUniqueViolation(error)) {
        return res.json({ saved: true });
      }
      console.error('Error saving post:', error);
      res.status(500).json({ error: 'Unable to save post.' });
    }
  });

  app.get('/api/posts/:id/comments', optionalAuth, async (req: AuthRequest, res: Response) => {
    try {
      const postId = parsePositiveInt(req.params.id);
      if (!postId) {
        return res.status(400).json({ error: 'Invalid post ID.' });
      }
      const viewer = req.currentUser;
      const [post] = await db.select().from(posts).where(eq(posts.id, postId)).limit(1);
      if (!canViewPost(viewer, post)) {
        return res.status(404).json({ error: 'Post not found.' });
      }

      let blockedSet = new Set<number>();
      if (viewer) {
        const blockRows = await db
          .select({ blockerId: blocks.blockerId, blockedId: blocks.blockedId })
          .from(blocks)
          .where(or(eq(blocks.blockerId, viewer.id), eq(blocks.blockedId, viewer.id)));
        for (const b of blockRows) {
          if (b.blockerId === viewer.id) blockedSet.add(b.blockedId);
          if (b.blockedId === viewer.id) blockedSet.add(b.blockerId);
        }
      }

      const rawComments = await db
        .select()
        .from(comments)
        .where(and(eq(comments.postId, postId), eq(comments.isHidden, false)))
        .orderBy(comments.createdAt);

      const commentRows =
        blockedSet.size > 0
          ? rawComments.filter((c) => !blockedSet.has(c.authorId))
          : rawComments;

      if (commentRows.length === 0) {
        return res.json([]);
      }

      const authorIds = Array.from(new Set(commentRows.map((c) => c.authorId)));
      const authorRows = await db
        .select()
        .from(users)
        .where(inArray(users.id, authorIds));
      const authorMap = new Map(authorRows.map((u) => [u.id, u]));

      res.json(
        commentRows.map((c) => {
          const author = authorMap.get(c.authorId);
          return {
            ...c,
            author: author ? sanitizeAuthorForViewer(author, viewer) : null,
          };
        })
      );
    } catch (error) {
      console.error('Error loading comments:', error);
      res.status(500).json({ error: 'Unable to load comments.' });
    }
  });

  app.post('/api/posts/:id/comments', requireAuth, requireVerified, async (req: AuthRequest, res: Response) => {
    try {
      const me = req.currentUser!;
      if (!checkRateLimit(`comment:${me.id}`, 25, 10 * 60 * 1000)) {
        return res.status(429).json({ error: 'Commenting too quickly. Please wait a moment.' });
      }

      const postId = parsePositiveInt(req.params.id);
      if (!postId) {
        return res.status(400).json({ error: 'Invalid post ID.' });
      }
      const content = typeof req.body?.content === 'string' ? req.body.content.trim() : '';
      if (content.length < 2 || content.length > 1500) {
        return res.status(400).json({ error: 'Comment must be between 2 and 1,500 characters.' });
      }

      const [post] = await db.select().from(posts).where(eq(posts.id, postId)).limit(1);
      if (!canViewPost(me, post)) {
        return res.status(404).json({ error: 'Post not found.' });
      }

      if (post.authorId !== me.id) {
        const blockCheck = await db
          .select({ id: blocks.id })
          .from(blocks)
          .where(
            or(
              and(eq(blocks.blockerId, post.authorId), eq(blocks.blockedId, me.id)),
              and(eq(blocks.blockerId, me.id), eq(blocks.blockedId, post.authorId))
            )
          )
          .limit(1);
        if (blockCheck.length > 0) {
          return res.status(403).json({ error: 'You cannot comment on this post.' });
        }
      }

      const created = await db.transaction(async (tx) => {
        const [commentRow] = await tx
          .insert(comments)
          .values({ postId, authorId: me.id, content })
          .returning();

        await tx
          .update(posts)
          .set({ commentsCount: sql`${posts.commentsCount} + 1` })
          .where(eq(posts.id, postId));

        if (post.authorId !== me.id) {
          await insertNotificationIfNotRecent(tx, {
            recipientId: post.authorId,
            actorId: me.id,
            type: 'comment',
            entityId: postId,
            message: `${me.displayName} commented on "${post.title.slice(0, 50)}"`,
          });
        }

        return commentRow;
      });

      res.status(201).json({
        comment: {
          ...created,
          author: sanitizePublicProfile(me, me),
        },
      });
    } catch (error) {
      console.error('Error adding comment:', error);
      res.status(500).json({ error: 'Unable to add comment.' });
    }
  });

  // Discover People & Profiles
  app.get('/api/discover/people', requireAuth, requireVerified, async (req: AuthRequest, res: Response) => {
    try {
      const viewer = req.currentUser!;
      const q = typeof req.query.q === 'string' ? req.query.q.trim() : '';
      const role = typeof req.query.role === 'string' ? req.query.role.trim() : '';
      const branch = typeof req.query.branch === 'string' ? req.query.branch.trim() : '';

      const conditions: any[] = [
        eq(users.isRestricted, false),
        eq(users.verificationStatus, 'verified'),
      ];

      if (viewer.role !== 'admin') {
        if (viewer.collegeId === null) {
          return res.json([]);
        }
        conditions.push(eq(users.collegeId, viewer.collegeId));
      }

      if (role && ['student', 'faculty', 'alumni'].includes(role)) {
        conditions.push(eq(users.role, role));
      }
      if (branch) {
        const branchPattern = `%${escapeLikePattern(branch)}%`;
        conditions.push(sql`${users.branch} ILIKE ${branchPattern} ESCAPE '\\'`);
      }
      if (q) {
        const pattern = `%${escapeLikePattern(q)}%`;
        conditions.push(
          or(
            sql`${users.displayName} ILIKE ${pattern} ESCAPE '\\'`,
            sql`${users.headline} ILIKE ${pattern} ESCAPE '\\'`,
            sql`${users.branch} ILIKE ${pattern} ESCAPE '\\'`,
            sql`array_to_string(${users.skills}, ' ') ILIKE ${pattern} ESCAPE '\\'`
          )
        );
      }

      const memberRows = await db
        .select()
        .from(users)
        .where(and(...conditions))
        .orderBy(desc(users.createdAt))
        .limit(40);

      const fRows = await db
        .select({ followingId: follows.followingId })
        .from(follows)
        .where(eq(follows.followerId, viewer.id));
      const followingIds = fRows.map((r) => r.followingId);

      const bRows = await db
        .select({ blockedId: blocks.blockedId })
        .from(blocks)
        .where(eq(blocks.blockerId, viewer.id));
      const blockedIds = bRows.map((b) => b.blockedId);

      const results = memberRows
        .filter((m) => !blockedIds.includes(m.id))
        .map((m) => ({
          ...sanitizePublicProfile(m, viewer),
          isFollowing: followingIds.includes(m.id),
        }));

      res.json(results);
    } catch (error) {
      console.error('Error discovering people:', error);
      res.status(500).json({ error: 'Unable to load campus directory.' });
    }
  });

  app.get('/api/users/:id', requireAuth, requireVerified, async (req: AuthRequest, res: Response) => {
    try {
      const targetId = parsePositiveInt(req.params.id);
      if (!targetId) {
        return res.status(400).json({ error: 'Invalid member ID.' });
      }
      const viewer = req.currentUser!;
      const [target] = await db.select().from(users).where(eq(users.id, targetId)).limit(1);
      if (!target || target.isRestricted) {
        return res.status(404).json({ error: 'Member not found.' });
      }

      const isSelf = viewer.id === target.id;
      const isAdmin = viewer.role === 'admin';

      if (target.verificationStatus !== 'verified' && !isSelf && !isAdmin) {
        return res.status(404).json({ error: 'Member not found.' });
      }

      if (
        !isAdmin &&
        !isSelf &&
        (viewer.collegeId === null || target.collegeId === null || target.collegeId !== viewer.collegeId)
      ) {
        return res.status(404).json({ error: 'Member not found.' });
      }

      const followerCount = await db
        .select({ count: sql<number>`count(*)::int` })
        .from(follows)
        .where(eq(follows.followingId, targetId));
      const followingCount = await db
        .select({ count: sql<number>`count(*)::int` })
        .from(follows)
        .where(eq(follows.followerId, targetId));

      const f = await db
        .select()
        .from(follows)
        .where(and(eq(follows.followerId, viewer.id), eq(follows.followingId, targetId)))
        .limit(1);
      const isFollowing = f.length > 0;

      const b = await db
        .select()
        .from(blocks)
        .where(and(eq(blocks.blockerId, viewer.id), eq(blocks.blockedId, targetId)))
        .limit(1);
      const isBlocked = b.length > 0;

      const canSeeCollegePosts =
        isAdmin ||
        isSelf ||
        (viewer.verificationStatus === 'verified' &&
          viewer.collegeId !== null &&
          target.collegeId !== null &&
          viewer.collegeId === target.collegeId);

      const userPosts = await db
        .select()
        .from(posts)
        .where(
          and(
            eq(posts.authorId, targetId),
            eq(posts.isHidden, false),
            canSeeCollegePosts ? sql`true` : eq(posts.visibility, 'public_preview')
          )
        )
        .orderBy(desc(posts.createdAt))
        .limit(10);

      res.json({
        user: sanitizePublicProfile(target, viewer),
        followersCount: followerCount[0]?.count ?? 0,
        followingCount: followingCount[0]?.count ?? 0,
        isFollowing,
        isBlocked,
        posts: userPosts,
      });
    } catch (error) {
      console.error('Error loading user profile:', error);
      res.status(500).json({ error: 'Unable to load member profile.' });
    }
  });

  app.post('/api/users/:id/follow', requireAuth, requireVerified, async (req: AuthRequest, res: Response) => {
    try {
      const me = req.currentUser!;
      if (!checkRateLimit(`follow:${me.id}`, 30, 10 * 60 * 1000)) {
        return res.status(429).json({ error: 'Too many follow actions. Please pause briefly.' });
      }
      const targetId = parsePositiveInt(req.params.id);
      if (!targetId) {
        return res.status(400).json({ error: 'Invalid member ID.' });
      }
      if (targetId === me.id) {
        return res.status(400).json({ error: 'You cannot follow yourself.' });
      }

      const [target] = await db
        .select({
          id: users.id,
          isRestricted: users.isRestricted,
          verificationStatus: users.verificationStatus,
        })
        .from(users)
        .where(eq(users.id, targetId))
        .limit(1);

      if (!target) {
        return res.status(404).json({ error: 'Member not found.' });
      }

      const existing = await db
        .select()
        .from(follows)
        .where(and(eq(follows.followerId, me.id), eq(follows.followingId, targetId)))
        .limit(1);

      if (existing.length > 0) {
        await db.delete(follows).where(eq(follows.id, existing[0].id));
        return res.json({ following: false });
      }

      if (target.isRestricted || target.verificationStatus !== 'verified') {
        return res.status(404).json({ error: 'Member not found.' });
      }

      const blockedPair = await db
        .select({ id: blocks.id })
        .from(blocks)
        .where(
          or(
            and(eq(blocks.blockerId, me.id), eq(blocks.blockedId, targetId)),
            and(eq(blocks.blockerId, targetId), eq(blocks.blockedId, me.id))
          )
        )
        .limit(1);
      if (blockedPair.length > 0) {
        return res.status(403).json({ error: 'You cannot follow this member.' });
      }

      await db.insert(follows).values({ followerId: me.id, followingId: targetId });
      await insertNotificationIfNotRecent(db, {
        recipientId: targetId,
        actorId: me.id,
        type: 'follow',
        entityId: me.id,
        message: `${me.displayName} started following you on CampusPath`,
      });
      return res.json({ following: true });
    } catch (error) {
      if (isPgUniqueViolation(error)) {
        return res.json({ following: true });
      }
      console.error('Error toggling follow:', error);
      res.status(500).json({ error: 'Unable to update follow status.' });
    }
  });

  app.post('/api/users/:id/block', requireAuth, async (req: AuthRequest, res: Response) => {
    try {
      const me = req.currentUser!;
      if (!checkRateLimit(`block:${me.id}`, 30, 10 * 60 * 1000)) {
        return res.status(429).json({ error: 'Too many block actions. Please pause briefly.' });
      }
      const targetId = parsePositiveInt(req.params.id);
      if (!targetId) {
        return res.status(400).json({ error: 'Invalid target.' });
      }
      if (targetId === me.id) {
        return res.status(400).json({ error: 'Invalid target.' });
      }

      const [target] = await db
        .select({ id: users.id })
        .from(users)
        .where(eq(users.id, targetId))
        .limit(1);
      if (!target) {
        return res.status(404).json({ error: 'Member not found.' });
      }

      const existing = await db
        .select()
        .from(blocks)
        .where(and(eq(blocks.blockerId, me.id), eq(blocks.blockedId, targetId)))
        .limit(1);

      if (existing.length > 0) {
        await db.delete(blocks).where(eq(blocks.id, existing[0].id));
        return res.json({ blocked: false });
      }

      try {
        await db.insert(blocks).values({ blockerId: me.id, blockedId: targetId });
      } catch (insertErr) {
        if (!isPgUniqueViolation(insertErr)) {
          throw insertErr;
        }
      }

      await db
        .delete(follows)
        .where(
          or(
            and(eq(follows.followerId, me.id), eq(follows.followingId, targetId)),
            and(eq(follows.followerId, targetId), eq(follows.followingId, me.id))
          )
        );
      return res.json({ blocked: true });
    } catch (error) {
      console.error('Error toggling block:', error);
      res.status(500).json({ error: 'Unable to update block setting.' });
    }
  });

  // Direct Messaging
  app.get('/api/conversations', requireAuth, requireVerified, async (req: AuthRequest, res: Response) => {
    try {
      const me = req.currentUser!;
      const myMemberships = await db
        .select()
        .from(conversationMembers)
        .where(eq(conversationMembers.userId, me.id));

      if (myMemberships.length === 0) {
        return res.json([]);
      }

      const convIds = myMemberships.map((m) => m.conversationId);
      const convRows = await db
        .select()
        .from(conversations)
        .where(inArray(conversations.id, convIds))
        .orderBy(desc(conversations.lastMessageAt));

      const allMembers = await db
        .select()
        .from(conversationMembers)
        .where(inArray(conversationMembers.conversationId, convIds));

      const peerIds = Array.from(
        new Set(allMembers.filter((m) => m.userId !== me.id).map((m) => m.userId))
      );
      const peerUsers =
        peerIds.length > 0
          ? await db.select().from(users).where(inArray(users.id, peerIds))
          : [];
      const peerMap = new Map(peerUsers.map((u) => [u.id, u]));

      const [latestMsgRows, unreadRows] = await Promise.all([
        db
          .selectDistinctOn([messages.conversationId], {
            id: messages.id,
            conversationId: messages.conversationId,
            senderId: messages.senderId,
            content: messages.content,
            createdAt: messages.createdAt,
          })
          .from(messages)
          .where(inArray(messages.conversationId, convIds))
          .orderBy(messages.conversationId, desc(messages.createdAt), desc(messages.id)),
        db
          .select({
            conversationId: messages.conversationId,
            count: sql<number>`count(*)::int`,
          })
          .from(messages)
          .innerJoin(
            conversationMembers,
            and(
              eq(conversationMembers.conversationId, messages.conversationId),
              eq(conversationMembers.userId, me.id)
            )
          )
          .where(
            and(
              inArray(messages.conversationId, convIds),
              ne(messages.senderId, me.id),
              sql`${messages.createdAt} > ${conversationMembers.lastReadAt}`
            )
          )
          .groupBy(messages.conversationId),
      ]);

      const latestMsgMap = new Map(latestMsgRows.map((m) => [m.conversationId, m]));
      const unreadMap = new Map(unreadRows.map((r) => [r.conversationId, r.count]));

      const list = convRows.map((conv) => {
        const peerMembership = allMembers.find(
          (m) => m.conversationId === conv.id && m.userId !== me.id
        );
        const peer = peerMembership ? peerMap.get(peerMembership.userId) : null;

        return {
          id: conv.id,
          lastMessageAt: conv.lastMessageAt,
          peer: peer ? sanitizePublicProfile(peer, me) : null,
          lastMessage: latestMsgMap.get(conv.id) ?? null,
          unreadCount: unreadMap.get(conv.id) ?? 0,
        };
      });

      res.json(list);
    } catch (error) {
      console.error('Error loading conversations:', error);
      res.status(500).json({ error: 'Unable to load conversations.' });
    }
  });

  app.post('/api/conversations', requireAuth, requireVerified, async (req: AuthRequest, res: Response) => {
    try {
      const me = req.currentUser!;
      const targetUserId = parsePositiveInt(req.body?.userId);
      if (!targetUserId || targetUserId === me.id) {
        return res.status(400).json({ error: 'Select a valid member to message.' });
      }

      const [target] = await db
        .select()
        .from(users)
        .where(eq(users.id, targetUserId))
        .limit(1);
      if (!target || target.isRestricted || target.verificationStatus !== 'verified') {
        return res.status(404).json({ error: 'Recipient is unavailable for messaging.' });
      }

      const blockedCheck = await db
        .select()
        .from(blocks)
        .where(
          or(
            and(eq(blocks.blockerId, me.id), eq(blocks.blockedId, targetUserId)),
            and(eq(blocks.blockerId, targetUserId), eq(blocks.blockedId, me.id))
          )
        )
        .limit(1);
      if (blockedCheck.length > 0) {
        return res.status(403).json({ error: 'Direct messaging is unavailable with this user.' });
      }

      const allowMessagesFrom = target.privacySettings?.allowMessagesFrom ?? 'college';
      if (allowMessagesFrom === 'followers') {
        const followsCheck = await db
          .select()
          .from(follows)
          .where(and(eq(follows.followerId, targetUserId), eq(follows.followingId, me.id)))
          .limit(1);
        if (followsCheck.length === 0) {
          return res.status(403).json({
            error: 'This member restricts messages to accounts they follow.',
          });
        }
      } else if (allowMessagesFrom === 'college') {
        if (
          me.role !== 'admin' &&
          (me.collegeId === null || target.collegeId === null || me.collegeId !== target.collegeId)
        ) {
          return res.status(403).json({
            error: 'This member only accepts direct messages from members of their own college.',
          });
        }
      }

      // Check existing 1:1 conversation
      const myConvs = await db
        .select({ conversationId: conversationMembers.conversationId })
        .from(conversationMembers)
        .where(eq(conversationMembers.userId, me.id));

      if (myConvs.length > 0) {
        const shared = await db
          .select()
          .from(conversationMembers)
          .where(
            and(
              inArray(
                conversationMembers.conversationId,
                myConvs.map((c) => c.conversationId)
              ),
              eq(conversationMembers.userId, targetUserId)
            )
          )
          .limit(1);

        if (shared.length > 0) {
          return res.json({ conversationId: shared[0].conversationId });
        }
      }

      if (!checkRateLimit(`create_conv:${me.id}`, 10, 60 * 60 * 1000)) {
        return res.status(429).json({
          error: 'New conversation limit reached. Please try again later.',
        });
      }

      const [createdConv] = await db
        .insert(conversations)
        .values({ collegeId: me.collegeId })
        .returning();

      await db.insert(conversationMembers).values([
        { conversationId: createdConv.id, userId: me.id },
        { conversationId: createdConv.id, userId: targetUserId },
      ]);

      res.status(201).json({ conversationId: createdConv.id });
    } catch (error) {
      console.error('Error starting conversation:', error);
      res.status(500).json({ error: 'Unable to open conversation.' });
    }
  });

  app.get('/api/conversations/:id/messages', requireAuth, requireVerified, async (req: AuthRequest, res: Response) => {
    try {
      const me = req.currentUser!;
      const convId = parsePositiveInt(req.params.id);
      if (!convId) {
        return res.status(400).json({ error: 'Invalid conversation ID.' });
      }

      let beforeId: number | null = null;
      if (req.query.before !== undefined && String(req.query.before).trim() !== '') {
        beforeId = parsePositiveInt(req.query.before);
        if (!beforeId) {
          return res.status(400).json({ error: 'Invalid before message ID.' });
        }
      }

      const membership = await db
        .select()
        .from(conversationMembers)
        .where(
          and(
            eq(conversationMembers.conversationId, convId),
            eq(conversationMembers.userId, me.id)
          )
        )
        .limit(1);

      if (membership.length === 0) {
        return res.status(403).json({ error: 'Access denied to this conversation.' });
      }

      await db
        .update(conversationMembers)
        .set({ lastReadAt: new Date() })
        .where(eq(conversationMembers.id, membership[0].id));

      const msgConditions = [eq(messages.conversationId, convId)];
      if (beforeId !== null) {
        msgConditions.push(lt(messages.id, beforeId));
      }

      const latestDesc = await db
        .select()
        .from(messages)
        .where(and(...msgConditions))
        .orderBy(desc(messages.createdAt), desc(messages.id))
        .limit(100);

      res.json(latestDesc.reverse());
    } catch (error) {
      console.error('Error loading messages:', error);
      res.status(500).json({ error: 'Unable to load conversation messages.' });
    }
  });

  app.post('/api/conversations/:id/messages', requireAuth, requireVerified, async (req: AuthRequest, res: Response) => {
    try {
      const me = req.currentUser!;
      if (!checkRateLimit(`dm:${me.id}`, 30, 5 * 60 * 1000)) {
        return res.status(429).json({ error: 'Messaging rate limit reached. Please pause briefly.' });
      }

      const convId = parsePositiveInt(req.params.id);
      if (!convId) {
        return res.status(400).json({ error: 'Invalid conversation ID.' });
      }
      const content = typeof req.body?.content === 'string' ? req.body.content.trim() : '';
      if (content.length < 1 || content.length > 2000) {
        return res.status(400).json({ error: 'Message must be between 1 and 2,000 characters.' });
      }

      const members = await db
        .select()
        .from(conversationMembers)
        .where(eq(conversationMembers.conversationId, convId));

      const isMember = members.some((m) => m.userId === me.id);
      if (!isMember) {
        return res.status(403).json({ error: 'Access denied to this conversation.' });
      }

      const peerIds = members.filter((m) => m.userId !== me.id).map((m) => m.userId);
      if (peerIds.length > 0) {
        const blockedCheck = await db
          .select()
          .from(blocks)
          .where(
            or(
              and(eq(blocks.blockerId, me.id), inArray(blocks.blockedId, peerIds)),
              and(inArray(blocks.blockerId, peerIds), eq(blocks.blockedId, me.id))
            )
          )
          .limit(1);
        if (blockedCheck.length > 0) {
          return res.status(403).json({ error: 'Cannot send messages to a blocked member.' });
        }
      }

      const [created] = await db
        .insert(messages)
        .values({ conversationId: convId, senderId: me.id, content })
        .returning();

      await db
        .update(conversations)
        .set({ lastMessageAt: new Date() })
        .where(eq(conversations.id, convId));

      await db
        .update(conversationMembers)
        .set({ lastReadAt: new Date() })
        .where(
          and(
            eq(conversationMembers.conversationId, convId),
            eq(conversationMembers.userId, me.id)
          )
        );

      for (const peerId of peerIds) {
        await insertNotificationIfNotRecent(db, {
          recipientId: peerId,
          actorId: me.id,
          type: 'message',
          entityId: convId,
          message: `New message from ${me.displayName}`,
        });
      }

      res.status(201).json({ message: created });
    } catch (error) {
      console.error('Error sending message:', error);
      res.status(500).json({ error: 'Unable to send message.' });
    }
  });

  // Notifications
  app.get('/api/notifications', requireAuth, async (req: AuthRequest, res: Response) => {
    try {
      const me = req.currentUser!;
      if (!checkRateLimit(`notif_get:${me.id}`, 60, 5 * 60 * 1000)) {
        return res.status(429).json({ error: 'Too many notification requests. Please wait briefly.' });
      }
      const rows = await db
        .select()
        .from(notifications)
        .where(eq(notifications.recipientId, me.id))
        .orderBy(desc(notifications.createdAt))
        .limit(40);
      res.json(rows);
    } catch (error) {
      console.error('Error fetching notifications:', error);
      res.status(500).json({ error: 'Unable to load notifications.' });
    }
  });

  app.post('/api/notifications/read-all', requireAuth, async (req: AuthRequest, res: Response) => {
    try {
      const me = req.currentUser!;
      if (!checkRateLimit(`notif_read:${me.id}`, 30, 5 * 60 * 1000)) {
        return res.status(429).json({ error: 'Too many requests. Please wait briefly.' });
      }
      await db
        .update(notifications)
        .set({ isRead: true })
        .where(eq(notifications.recipientId, me.id));
      res.json({ ok: true });
    } catch (error) {
      console.error('Error marking notifications read:', error);
      res.status(500).json({ error: 'Unable to update notifications.' });
    }
  });

  // Reports
  app.post('/api/reports', requireAuth, async (req: AuthRequest, res: Response) => {
    try {
      const me = req.currentUser!;
      if (!checkRateLimit(`report:${me.id}`, 10, 60 * 60 * 1000)) {
        return res.status(429).json({
          error: 'Report submission limit reached. Please wait before submitting another report.',
        });
      }

      const { targetType, targetId, reason, details, priority } = req.body || {};
      if (!['post', 'comment', 'user', 'message'].includes(targetType)) {
        return res.status(400).json({ error: 'Invalid report target type.' });
      }
      const parsedTargetId = parsePositiveInt(targetId);
      if (!parsedTargetId) {
        return res.status(400).json({ error: 'Invalid target ID.' });
      }
      if (typeof reason !== 'string' || reason.trim().length < 3) {
        return res.status(400).json({ error: 'Please provide a report reason.' });
      }

      let targetExists = false;
      if (targetType === 'post') {
        const rows = await db
          .select({ id: posts.id })
          .from(posts)
          .where(eq(posts.id, parsedTargetId))
          .limit(1);
        targetExists = rows.length > 0;
      } else if (targetType === 'comment') {
        const rows = await db
          .select({ id: comments.id })
          .from(comments)
          .where(eq(comments.id, parsedTargetId))
          .limit(1);
        targetExists = rows.length > 0;
      } else if (targetType === 'user') {
        const rows = await db
          .select({ id: users.id })
          .from(users)
          .where(eq(users.id, parsedTargetId))
          .limit(1);
        targetExists = rows.length > 0;
      } else if (targetType === 'message') {
        const rows = await db
          .select({ id: messages.id })
          .from(messages)
          .where(eq(messages.id, parsedTargetId))
          .limit(1);
        targetExists = rows.length > 0;
      }

      if (!targetExists) {
        return res.status(404).json({ error: 'Reported target not found.' });
      }

      const duplicateOpen = await db
        .select({ id: reports.id })
        .from(reports)
        .where(
          and(
            eq(reports.reporterId, me.id),
            eq(reports.targetType, targetType),
            eq(reports.targetId, parsedTargetId),
            eq(reports.status, 'open')
          )
        )
        .limit(1);

      if (duplicateOpen.length > 0) {
        return res.status(409).json({
          error: 'You already have an open report for this item.',
        });
      }

      const safePriority = ['low', 'medium', 'high'].includes(priority) ? priority : 'medium';

      const [created] = await db
        .insert(reports)
        .values({
          reporterId: me.id,
          targetType,
          targetId: parsedTargetId,
          reason: reason.trim().slice(0, 120),
          details: typeof details === 'string' ? details.trim().slice(0, 1000) : '',
          priority: safePriority,
        })
        .returning();

      res.status(201).json({ report: created });
    } catch (error) {
      console.error('Error filing report:', error);
      res.status(500).json({ error: 'Unable to submit report.' });
    }
  });

  // Admin & Moderator Console
  app.get(
    '/api/admin/overview',
    requireAuth,
    requireRole(['admin', 'moderator']),
    async (req: AuthRequest, res: Response) => {
      try {
        const me = req.currentUser!;

        // Moderators must have a collegeId and receive ONLY reports for targets in their own college
        // (omitting reporterId and reviewedBy, and never exposing verifications, members, colleges, or auditLogs).
        if (me.role !== 'admin') {
          if (me.collegeId === null) {
            return res.status(403).json({
              error: 'Moderator accounts must be assigned to a college.',
            });
          }

          const modCollegeId = me.collegeId;
          const scopedReports = await db
            .select({
              id: reports.id,
              targetType: reports.targetType,
              targetId: reports.targetId,
              reason: reports.reason,
              details: reports.details,
              priority: reports.priority,
              status: reports.status,
              resolutionNotes: reports.resolutionNotes,
              createdAt: reports.createdAt,
              resolvedAt: reports.resolvedAt,
            })
            .from(reports)
            .where(
              or(
                and(
                  eq(reports.targetType, 'post'),
                  sql`EXISTS (SELECT 1 FROM posts p WHERE p.id = ${reports.targetId} AND p.college_id = ${modCollegeId})`
                ),
                and(
                  eq(reports.targetType, 'comment'),
                  sql`EXISTS (SELECT 1 FROM comments c INNER JOIN posts p ON p.id = c.post_id WHERE c.id = ${reports.targetId} AND p.college_id = ${modCollegeId})`
                ),
                and(
                  eq(reports.targetType, 'user'),
                  sql`EXISTS (SELECT 1 FROM users u WHERE u.id = ${reports.targetId} AND u.college_id = ${modCollegeId})`
                ),
                and(
                  eq(reports.targetType, 'message'),
                  sql`EXISTS (SELECT 1 FROM messages m LEFT JOIN conversations conv ON conv.id = m.conversation_id LEFT JOIN users u ON u.id = m.sender_id WHERE m.id = ${reports.targetId} AND COALESCE(conv.college_id, u.college_id) = ${modCollegeId})`
                )
              )
            )
            .orderBy(desc(reports.createdAt))
            .limit(40);

          return res.json({
            verifications: [],
            reports: scopedReports,
            members: [],
            colleges: [],
            auditLogs: [],
          });
        }

        const verificationSelection = {
          id: verificationRequests.id,
          userId: verificationRequests.userId,
          collegeId: verificationRequests.collegeId,
          requestedRole: verificationRequests.requestedRole,
          collegeEmail: verificationRequests.collegeEmail,
          method: verificationRequests.method,
          evidenceNote: verificationRequests.evidenceNote,
          status: verificationRequests.status,
          reviewedBy: verificationRequests.reviewedBy,
          reviewNotes: verificationRequests.reviewNotes,
          createdAt: verificationRequests.createdAt,
          reviewedAt: verificationRequests.reviewedAt,
        };

        const [pendingVerifications, decidedVerifications] = await Promise.all([
          db
            .select(verificationSelection)
            .from(verificationRequests)
            .where(eq(verificationRequests.status, 'pending'))
            .orderBy(asc(verificationRequests.createdAt), asc(verificationRequests.id))
            .limit(200),
          db
            .select(verificationSelection)
            .from(verificationRequests)
            .where(ne(verificationRequests.status, 'pending'))
            .orderBy(desc(verificationRequests.reviewedAt), desc(verificationRequests.createdAt))
            .limit(20),
        ]);

        const verificationQueue = [...pendingVerifications, ...decidedVerifications];

        const queueUserIds = Array.from(new Set(verificationQueue.map((v) => v.userId)));
        const queueUsers =
          queueUserIds.length > 0
            ? await db
                .select({
                  id: users.id,
                  displayName: users.displayName,
                  email: users.email,
                  branch: users.branch,
                })
                .from(users)
                .where(inArray(users.id, queueUserIds))
            : [];
        const queueUserMap = new Map(queueUsers.map((u) => [u.id, u]));

        const reportQueue = await db
          .select()
          .from(reports)
          .orderBy(desc(reports.createdAt))
          .limit(40);

        const memberQ = typeof req.query.memberQ === 'string' ? req.query.memberQ.trim() : '';
        const memberOffset = parseNonNegativeInt(req.query.memberOffset);
        const memberPattern = memberQ ? `%${escapeLikePattern(memberQ)}%` : null;

        const memberRows = await db
          .select({
            id: users.id,
            displayName: users.displayName,
            email: users.email,
            role: users.role,
            verificationStatus: users.verificationStatus,
            collegeId: users.collegeId,
            branch: users.branch,
            isRestricted: users.isRestricted,
            createdAt: users.createdAt,
          })
          .from(users)
          .where(
            memberPattern
              ? or(
                  sql`${users.displayName} ILIKE ${memberPattern} ESCAPE '\\'`,
                  sql`${users.email} ILIKE ${memberPattern} ESCAPE '\\'`
                )
              : undefined
          )
          .orderBy(desc(users.createdAt), desc(users.id))
          .limit(60)
          .offset(memberOffset);

        const collegeRows = await db.select().from(colleges).orderBy(colleges.id);

        const logs = await db
          .select()
          .from(auditLogs)
          .orderBy(desc(auditLogs.createdAt))
          .limit(40);

        res.json({
          verifications: verificationQueue.map((v) => ({
            ...v,
            evidenceNote:
              v.status === 'pending' ? v.evidenceNote : '[Redacted after decision]',
            user: queueUserMap.get(v.userId) ?? null,
          })),
          reports: reportQueue,
          members: memberRows,
          colleges: collegeRows,
          auditLogs: logs,
        });
      } catch (error) {
        console.error('Error loading admin overview:', error);
        res.status(500).json({ error: 'Unable to load admin console.' });
      }
    }
  );

  // Admin-only non-destructive verification provenance audit
  app.get(
    '/api/admin/verification-audit',
    requireAuth,
    requireRole(['admin']),
    async (_req: AuthRequest, res: Response) => {
      try {
        const allVerifiedOrAdmin = await db
          .select({
            id: users.id,
            uid: users.uid,
            email: users.email,
            displayName: users.displayName,
            role: users.role,
            verificationStatus: users.verificationStatus,
            collegeId: users.collegeId,
            createdAt: users.createdAt,
          })
          .from(users)
          .where(or(eq(users.verificationStatus, 'verified'), eq(users.role, 'admin')))
          .orderBy(users.id);

        const userIds = allVerifiedOrAdmin.map((u) => u.id);
        const approvedReqs =
          userIds.length > 0
            ? await db
                .select({
                  userId: verificationRequests.userId,
                  method: verificationRequests.method,
                  status: verificationRequests.status,
                  reviewedAt: verificationRequests.reviewedAt,
                })
                .from(verificationRequests)
                .where(
                  and(
                    inArray(verificationRequests.userId, userIds),
                    eq(verificationRequests.status, 'approved')
                  )
                )
            : [];

        const memberUpdateLogs =
          userIds.length > 0
            ? await db
                .select({
                  targetId: auditLogs.targetId,
                  action: auditLogs.action,
                  metadata: auditLogs.metadata,
                  createdAt: auditLogs.createdAt,
                })
                .from(auditLogs)
                .where(
                  and(
                    eq(auditLogs.action, 'ADMIN_MEMBER_UPDATED'),
                    eq(auditLogs.targetType, 'user'),
                    inArray(auditLogs.targetId, userIds)
                  )
                )
            : [];

        const configuredBootstrapEmail = getConfiguredBootstrapAdminEmail();
        const reqsByUser = new Map<number, typeof approvedReqs>();
        for (const r of approvedReqs) {
          const list = reqsByUser.get(r.userId) || [];
          list.push(r);
          reqsByUser.set(r.userId, list);
        }

        const logsByUser = new Map<number, typeof memberUpdateLogs>();
        for (const l of memberUpdateLogs) {
          if (l.targetId === null) continue;
          const list = logsByUser.get(l.targetId) || [];
          list.push(l);
          logsByUser.set(l.targetId, list);
        }

        const accounts = allVerifiedOrAdmin.map((u) => {
          const isSeedAccount = u.uid.startsWith('seed_');
          const uReqs = reqsByUser.get(u.id) || [];
          const uLogs = logsByUser.get(u.id) || [];
          const normalizedEmail = u.email.trim().toLowerCase();

          const wasPromotedToAdmin = uLogs.some(
            (l) => (l.metadata as Record<string, unknown>)?.role === 'admin'
          );
          const wasVerifiedByAdminAction = uLogs.some(
            (l) => (l.metadata as Record<string, unknown>)?.verificationStatus === 'verified'
          );
          const hasAdminReviewApproval = uReqs.some((r) => r.method === 'admin_review');
          const hasLegacyEmailOtpApproval = uReqs.some((r) => r.method === 'email_otp');

          let provenance:
            | 'promoted_admin'
            | 'configured_bootstrap_admin'
            | 'unknown_or_manual_admin'
            | 'admin_review_approved'
            | 'verified_by_admin_action'
            | 'legacy_email_otp'
            | 'auto_verified_or_unknown';

          if (u.role === 'admin') {
            if (wasPromotedToAdmin) {
              provenance = 'promoted_admin';
            } else if (
              Boolean(configuredBootstrapEmail) &&
              normalizedEmail === configuredBootstrapEmail
            ) {
              provenance = 'configured_bootstrap_admin';
            } else {
              provenance = 'unknown_or_manual_admin';
            }
          } else if (hasAdminReviewApproval) {
            provenance = 'admin_review_approved';
          } else if (wasVerifiedByAdminAction) {
            provenance = 'verified_by_admin_action';
          } else if (hasLegacyEmailOtpApproval) {
            provenance = 'legacy_email_otp';
          } else {
            provenance = 'auto_verified_or_unknown';
          }

          const needsReview =
            !isSeedAccount &&
            (provenance === 'legacy_email_otp' ||
              provenance === 'auto_verified_or_unknown' ||
              provenance === 'unknown_or_manual_admin');

          return {
            id: u.id,
            displayName: u.displayName,
            role: u.role,
            verificationStatus: u.verificationStatus,
            collegeId: u.collegeId,
            isSeedAccount,
            provenance,
            needsReview,
            createdAt: u.createdAt,
          };
        });

        const summary = accounts.reduce<Record<string, number>>((acc, row) => {
          acc[row.provenance] = (acc[row.provenance] || 0) + 1;
          return acc;
        }, {});

        res.json({
          totalAudited: accounts.length,
          flaggedForReview: accounts.filter((a) => a.needsReview).length,
          summary,
          accounts,
        });
      } catch (error) {
        console.error('Error generating verification provenance audit:', error);
        res.status(500).json({ error: 'Unable to run verification audit.' });
      }
    }
  );

  app.post(
    '/api/admin/verifications/:id/decide',
    requireAuth,
    requireRole(['admin']),
    async (req: AuthRequest, res: Response) => {
      try {
        const me = req.currentUser!;
        const reqId = parsePositiveInt(req.params.id);
        if (!reqId) {
          return res.status(400).json({ error: 'Invalid verification request ID.' });
        }
        const { decision, reviewNotes } = req.body || {};
        if (!['approved', 'rejected'].includes(decision)) {
          return res.status(400).json({ error: 'Decision must be approved or rejected.' });
        }
        const safeReviewNotes =
          typeof reviewNotes === 'string' ? reviewNotes.trim().slice(0, 400) : '';

        await db.transaction(async (tx) => {
          // Atomic compare-and-set: only transition rows that are still 'pending'
          // Also clear evidenceNote upon decision to minimize retained sensitive data.
          const [updatedReq] = await tx
            .update(verificationRequests)
            .set({
              status: decision,
              reviewedBy: me.id,
              reviewNotes: safeReviewNotes,
              evidenceNote: '',
              reviewedAt: new Date(),
            })
            .where(
              and(
                eq(verificationRequests.id, reqId),
                eq(verificationRequests.status, 'pending')
              )
            )
            .returning();

          if (!updatedReq) {
            const [existing] = await tx
              .select({ id: verificationRequests.id, status: verificationRequests.status })
              .from(verificationRequests)
              .where(eq(verificationRequests.id, reqId))
              .limit(1);
            if (!existing) {
              throw new HttpError(404, 'Verification request not found.');
            }
            throw new HttpError(
              409,
              `Verification request has already been ${existing.status}.`,
              'ALREADY_DECIDED'
            );
          }

          const [targetUser] = await tx
            .select()
            .from(users)
            .where(eq(users.id, updatedReq.userId))
            .limit(1);
          if (!targetUser) {
            throw new HttpError(404, 'Applicant account not found.');
          }

          if (decision === 'approved') {
            const [activeCollege] = await tx
              .select({ id: colleges.id })
              .from(colleges)
              .where(
                and(eq(colleges.id, updatedReq.collegeId), eq(colleges.status, 'active'))
              )
              .limit(1);
            if (!activeCollege) {
              throw new HttpError(
                400,
                'Cannot approve verification because the requested college is inactive or missing.'
              );
            }

            const preservedPrivilegedRole =
              targetUser.role === 'admin' || targetUser.role === 'moderator';
            const nextRole = preservedPrivilegedRole
              ? targetUser.role
              : ['student', 'faculty', 'alumni'].includes(updatedReq.requestedRole)
              ? updatedReq.requestedRole
              : 'student';

            await tx
              .update(users)
              .set({
                verificationStatus: 'verified',
                role: nextRole,
                collegeId: activeCollege.id,
                collegeEmail: updatedReq.collegeEmail || targetUser.collegeEmail,
                updatedAt: new Date(),
              })
              .where(eq(users.id, targetUser.id));
          } else {
            // Rejection never overwrites collegeId and never demotes privileged roles
            await tx
              .update(users)
              .set({
                verificationStatus: 'rejected',
                updatedAt: new Date(),
              })
              .where(eq(users.id, targetUser.id));
          }

          await tx.insert(notifications).values({
            recipientId: updatedReq.userId,
            actorId: me.id,
            type: 'verification',
            entityId: updatedReq.id,
            message:
              decision === 'approved'
                ? 'Your CampusPath college membership has been verified.'
                : `Your verification request was not approved: ${safeReviewNotes || 'Please submit clearer campus details.'}`,
          });

          await tx.insert(auditLogs).values({
            actorId: me.id,
            action: `VERIFICATION_${decision.toUpperCase()}`,
            targetType: 'verification_request',
            targetId: reqId,
            reason: safeReviewNotes,
            metadata: {
              userId: updatedReq.userId,
              requestedRole: updatedReq.requestedRole,
              collegeId: updatedReq.collegeId,
            },
          });
        });

        res.json({ ok: true });
      } catch (error) {
        if (error instanceof HttpError) {
          return res
            .status(error.status)
            .json({ error: error.message, ...(error.code ? { code: error.code } : {}) });
        }
        console.error('Error deciding verification:', error);
        res.status(500).json({ error: 'Unable to update verification request.' });
      }
    }
  );

  app.post(
    '/api/admin/reports/:id/decide',
    requireAuth,
    requireRole(['admin', 'moderator']),
    async (req: AuthRequest, res: Response) => {
      try {
        const me = req.currentUser!;
        if (me.role === 'moderator' && me.collegeId === null) {
          return res.status(403).json({
            error: 'Moderator accounts must be assigned to a college.',
          });
        }
        const reportId = parsePositiveInt(req.params.id);
        if (!reportId) {
          return res.status(400).json({ error: 'Invalid report ID.' });
        }
        const { status, resolutionNotes, hideTarget } = req.body || {};
        if (!['reviewing', 'resolved', 'dismissed'].includes(status)) {
          return res.status(400).json({ error: 'Invalid report status.' });
        }
        const safeResolutionNotes =
          typeof resolutionNotes === 'string' ? resolutionNotes.trim().slice(0, 500) : '';

        await db.transaction(async (tx) => {
          const [rep] = await tx
            .select()
            .from(reports)
            .where(eq(reports.id, reportId))
            .limit(1);
          if (!rep) {
            throw new HttpError(404, 'Report not found.');
          }

          if (me.role === 'moderator') {
            const targetCollegeId = await resolveReportTargetCollegeId(
              tx,
              rep.targetType,
              rep.targetId
            );
            if (targetCollegeId === null || targetCollegeId !== me.collegeId) {
              throw new HttpError(
                403,
                'Moderators can only act on reports within their own college.'
              );
            }
          }

          if (hideTarget && rep.targetType === 'user') {
            if (rep.targetId === me.id) {
              throw new HttpError(403, 'You cannot restrict your own account.');
            }
            const [targetUser] = await tx
              .select({ id: users.id, role: users.role })
              .from(users)
              .where(eq(users.id, rep.targetId))
              .limit(1);
            if (!targetUser) {
              throw new HttpError(404, 'Reported user not found.');
            }
            if (
              me.role === 'moderator' &&
              (targetUser.role === 'admin' || targetUser.role === 'moderator')
            ) {
              throw new HttpError(
                403,
                'Moderators cannot restrict administrator or moderator accounts.'
              );
            }
          }

          await tx
            .update(reports)
            .set({
              status,
              resolutionNotes: safeResolutionNotes,
              reviewedBy: me.id,
              resolvedAt: status === 'resolved' || status === 'dismissed' ? new Date() : null,
            })
            .where(eq(reports.id, reportId));

          if (hideTarget && rep.targetType === 'post') {
            await tx.update(posts).set({ isHidden: true }).where(eq(posts.id, rep.targetId));
          } else if (hideTarget && rep.targetType === 'comment') {
            await tx.update(comments).set({ isHidden: true }).where(eq(comments.id, rep.targetId));
          } else if (hideTarget && rep.targetType === 'user') {
            await tx
              .update(users)
              .set({ isRestricted: true, updatedAt: new Date() })
              .where(eq(users.id, rep.targetId));
          }

          await tx.insert(auditLogs).values({
            actorId: me.id,
            action: `REPORT_${status.toUpperCase()}`,
            targetType: rep.targetType,
            targetId: rep.targetId,
            reason: safeResolutionNotes,
            metadata: { reportId, hideTarget: Boolean(hideTarget) },
          });
        });

        res.json({ ok: true });
      } catch (error) {
        if (error instanceof HttpError) {
          return res
            .status(error.status)
            .json({ error: error.message, ...(error.code ? { code: error.code } : {}) });
        }
        console.error('Error deciding report:', error);
        res.status(500).json({ error: 'Unable to resolve report.' });
      }
    }
  );

  app.post(
    '/api/admin/users/:id/role',
    requireAuth,
    requireRole(['admin']),
    async (req: AuthRequest, res: Response) => {
      try {
        const me = req.currentUser!;
        const targetId = parsePositiveInt(req.params.id);
        if (!targetId) {
          return res.status(400).json({ error: 'Invalid member ID.' });
        }
        const { role, isRestricted, verificationStatus, collegeId } = req.body || {};

        await db.transaction(async (tx) => {
          const [target] = await tx
            .select()
            .from(users)
            .where(eq(users.id, targetId))
            .limit(1);
          if (!target) {
            throw new HttpError(404, 'Member not found.');
          }

          const updates: Record<string, unknown> = { updatedAt: new Date() };

          if (role !== undefined) {
            if (!['student', 'faculty', 'alumni', 'moderator', 'admin'].includes(role)) {
              throw new HttpError(400, 'Invalid member role specified.');
            }
            if (targetId === me.id && role !== 'admin') {
              throw new HttpError(400, 'You cannot demote your own administrator account.');
            }
            updates.role = role;
          }

          if (isRestricted !== undefined) {
            if (typeof isRestricted !== 'boolean') {
              throw new HttpError(400, 'isRestricted must be a boolean.');
            }
            if (targetId === me.id && isRestricted) {
              throw new HttpError(400, 'You cannot restrict your own administrator account.');
            }
            updates.isRestricted = isRestricted;
          }

          if (verificationStatus !== undefined) {
            if (!['unverified', 'pending', 'verified', 'rejected'].includes(verificationStatus)) {
              throw new HttpError(400, 'Invalid verification status specified.');
            }
            updates.verificationStatus = verificationStatus;
          }

          let nextCollegeId: number | null | undefined = undefined;
          if (collegeId !== undefined) {
            if (collegeId === null) {
              nextCollegeId = null;
              updates.collegeId = null;
            } else {
              const parsedCollegeId = parsePositiveInt(collegeId);
              if (!parsedCollegeId) {
                throw new HttpError(400, 'Invalid college ID.');
              }
              const [activeCollege] = await tx
                .select({ id: colleges.id })
                .from(colleges)
                .where(and(eq(colleges.id, parsedCollegeId), eq(colleges.status, 'active')))
                .limit(1);
              if (!activeCollege) {
                throw new HttpError(
                  400,
                  'Selected college does not exist or is currently inactive.'
                );
              }
              nextCollegeId = activeCollege.id;
              updates.collegeId = activeCollege.id;
            }
          }

          const effectiveVerificationStatus =
            (updates.verificationStatus as string | undefined) ?? target.verificationStatus;
          const effectiveCollegeId =
            nextCollegeId !== undefined ? nextCollegeId : target.collegeId;

          if (effectiveVerificationStatus === 'verified') {
            if (effectiveCollegeId === null) {
              throw new HttpError(
                400,
                'An active college must be assigned before marking a member verified.'
              );
            }
            const [assignedActiveCollege] = await tx
              .select({ id: colleges.id })
              .from(colleges)
              .where(and(eq(colleges.id, effectiveCollegeId), eq(colleges.status, 'active')))
              .limit(1);
            if (!assignedActiveCollege) {
              throw new HttpError(
                400,
                'Cannot mark member verified without a valid active college assignment.'
              );
            }
          }

          await tx.update(users).set(updates).where(eq(users.id, targetId));

          await tx.insert(auditLogs).values({
            actorId: me.id,
            action: 'ADMIN_MEMBER_UPDATED',
            targetType: 'user',
            targetId,
            reason: 'Administrative role or status adjustment',
            metadata: {
              ...(updates.role !== undefined ? { role: updates.role } : {}),
              ...(updates.isRestricted !== undefined
                ? { isRestricted: updates.isRestricted }
                : {}),
              ...(updates.verificationStatus !== undefined
                ? { verificationStatus: updates.verificationStatus }
                : {}),
              ...(updates.collegeId !== undefined ? { collegeId: updates.collegeId } : {}),
            },
          });
        });

        res.json({ ok: true });
      } catch (error) {
        if (error instanceof HttpError) {
          return res
            .status(error.status)
            .json({ error: error.message, ...(error.code ? { code: error.code } : {}) });
        }
        console.error('Error updating member role:', error);
        res.status(500).json({ error: 'Unable to update member.' });
      }
    }
  );

  app.post(
    '/api/admin/colleges',
    requireAuth,
    requireRole(['admin']),
    async (req: AuthRequest, res: Response) => {
      try {
        const me = req.currentUser!;
        const { name, location, approvedDomains, description } = req.body || {};
        if (typeof name !== 'string' || name.trim().length < 3) {
          return res.status(400).json({ error: 'College name is required.' });
        }
        const slug = name
          .trim()
          .toLowerCase()
          .replace(/[^a-z0-9]+/g, '-')
          .replace(/^-|-$/g, '');
        if (!slug) {
          return res.status(400).json({ error: 'Enter a valid college name.' });
        }

        const rawDomains = Array.isArray(approvedDomains)
          ? approvedDomains.filter((d): d is string => typeof d === 'string')
          : typeof approvedDomains === 'string'
          ? approvedDomains.split(',')
          : [];

        const validatedDomains: string[] = [];
        const seenDomains = new Set<string>();
        for (const raw of rawDomains) {
          if (!raw.trim()) continue;
          const result = validateCollegeDomain(raw);
          if (!result.valid) {
            return res.status(400).json({ error: result.error });
          }
          if (!seenDomains.has(result.domain)) {
            seenDomains.add(result.domain);
            validatedDomains.push(result.domain);
          }
        }

        const [created] = await db
          .insert(colleges)
          .values({
            name: name.trim().slice(0, 120),
            slug,
            location: typeof location === 'string' ? location.trim().slice(0, 120) : '',
            approvedDomains: validatedDomains,
            description: typeof description === 'string' ? description.trim().slice(0, 500) : '',
          })
          .returning();

        await db.insert(auditLogs).values({
          actorId: me.id,
          action: 'COLLEGE_CREATED',
          targetType: 'college',
          targetId: created.id,
          reason: 'Added partner college to CampusPath',
          metadata: { name: created.name, domains: validatedDomains },
        });

        res.status(201).json({ college: created });
      } catch (error) {
        if (isPgUniqueViolation(error)) {
          return res.status(409).json({ error: 'A college with this name already exists.' });
        }
        console.error('Error creating college:', error);
        res.status(500).json({ error: 'Unable to add college.' });
      }
    }
  );

  app.patch(
    '/api/admin/colleges/:id',
    requireAuth,
    requireRole(['admin']),
    async (req: AuthRequest, res: Response) => {
      try {
        const me = req.currentUser!;
        const collegeId = parsePositiveInt(req.params.id);
        if (!collegeId) {
          return res.status(400).json({ error: 'Invalid college ID.' });
        }

        const [existing] = await db
          .select()
          .from(colleges)
          .where(eq(colleges.id, collegeId))
          .limit(1);
        if (!existing) {
          return res.status(404).json({ error: 'College not found.' });
        }

        const { name, location, description, status, approvedDomains } = req.body || {};

        let nextName = existing.name;
        if (name !== undefined) {
          if (typeof name !== 'string' || name.trim().length < 3) {
            return res.status(400).json({ error: 'College name must be at least 3 characters.' });
          }
          nextName = name.trim().slice(0, 120);
        }

        let nextLocation = existing.location;
        if (location !== undefined) {
          if (typeof location !== 'string') {
            return res.status(400).json({ error: 'Invalid location value.' });
          }
          nextLocation = location.trim().slice(0, 120);
        }

        let nextDescription = existing.description;
        if (description !== undefined) {
          if (typeof description !== 'string') {
            return res.status(400).json({ error: 'Invalid description value.' });
          }
          nextDescription = description.trim().slice(0, 500);
        }

        let nextStatus = existing.status;
        if (status !== undefined) {
          if (status !== 'active' && status !== 'inactive') {
            return res.status(400).json({ error: 'Status must be active or inactive.' });
          }
          nextStatus = status;
        }

        let nextApprovedDomains = existing.approvedDomains;
        if (approvedDomains !== undefined) {
          const rawDomains = Array.isArray(approvedDomains)
            ? approvedDomains.filter((d): d is string => typeof d === 'string')
            : typeof approvedDomains === 'string'
            ? approvedDomains.split(',')
            : null;
          if (!rawDomains) {
            return res.status(400).json({ error: 'Invalid approved domains format.' });
          }

          const validatedDomains: string[] = [];
          const seenDomains = new Set<string>();
          for (const raw of rawDomains) {
            if (!raw.trim()) continue;
            const result = validateCollegeDomain(raw);
            if (!result.valid) {
              return res.status(400).json({ error: result.error });
            }
            if (!seenDomains.has(result.domain)) {
              seenDomains.add(result.domain);
              validatedDomains.push(result.domain);
            }
          }
          nextApprovedDomains = validatedDomains;
        }

        const [updated] = await db
          .update(colleges)
          .set({
            name: nextName,
            location: nextLocation,
            description: nextDescription,
            status: nextStatus,
            approvedDomains: nextApprovedDomains,
          })
          .where(eq(colleges.id, collegeId))
          .returning();

        await db.insert(auditLogs).values({
          actorId: me.id,
          action: 'COLLEGE_UPDATED',
          targetType: 'college',
          targetId: updated.id,
          reason: 'Updated partner college details',
          metadata: {
            name: updated.name,
            location: updated.location,
            status: updated.status,
            domains: updated.approvedDomains,
          },
        });

        res.json({ college: updated });
      } catch (error) {
        if (isPgUniqueViolation(error)) {
          return res.status(409).json({ error: 'A college with this name already exists.' });
        }
        console.error('Error updating college:', error);
        res.status(500).json({ error: 'Unable to update college.' });
      }
    }
  );

  if (process.env.NODE_ENV !== 'production') {
    const { createServer: createViteServer } = await import('vite');
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distDir = path.resolve(process.cwd(), 'dist');
    app.use(express.static(distDir));
    app.get('*', (_req, res) => {
      res.sendFile(path.join(distDir, 'index.html'));
    });
  }

  // Centralized error handler (Multer errors, malformed JSON, and safe generic 500s)
  app.use((err: unknown, _req: Request, res: Response, _next: NextFunction) => {
    if (res.headersSent) {
      return;
    }
    if (err instanceof multer.MulterError) {
      if (err.code === 'LIMIT_FILE_SIZE') {
        return res.status(400).json({ error: 'File exceeds the 10 MB maximum size limit.' });
      }
      if (err.code === 'LIMIT_FILE_COUNT') {
        return res.status(400).json({ error: 'You can attach up to 3 files per post.' });
      }
      if (err.code === 'LIMIT_UNEXPECTED_FILE') {
        return res.status(400).json({ error: 'Unexpected file upload field.' });
      }
      return res.status(400).json({ error: 'Invalid file upload.' });
    }
    if (err instanceof SyntaxError && 'body' in err) {
      const syntaxStatus = (err as SyntaxError & { status?: unknown }).status;
      if (syntaxStatus === 400) {
        return res.status(400).json({ error: 'Invalid JSON request body.' });
      }
    }
    if (err instanceof HttpError) {
      return res
        .status(err.status)
        .json({ error: err.message, ...(err.code ? { code: err.code } : {}) });
    }
    console.error('Unhandled server error:', err);
    return res.status(500).json({ error: 'Internal server error.' });
  });

  const server = app.listen(PORT, '0.0.0.0', () => {
    console.log(`CampusPath server running on port ${PORT}`);
  });

  let shuttingDown = false;
  const gracefulShutdown = (signal: string) => {
    if (shuttingDown) return;
    shuttingDown = true;
    console.log(`Received ${signal}. Closing HTTP server and PostgreSQL pool...`);
    clearInterval(rateLimitCleanupTimer);

    const forceExitTimer = setTimeout(() => {
      console.error('Graceful shutdown timed out; forcing exit.');
      process.exit(1);
    }, 10_000);
    forceExitTimer.unref();

    server.close(async (closeErr) => {
      if (closeErr) {
        console.error('Error closing HTTP server:', closeErr);
      }
      try {
        await pool.end();
      } catch (poolErr) {
        console.error('Error closing PostgreSQL pool:', poolErr);
      }
      clearTimeout(forceExitTimer);
      process.exit(closeErr ? 1 : 0);
    });
  };

  process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
}

startServer().catch((err) => {
  console.error('Fatal server startup error:', err);
  process.exit(1);
});
