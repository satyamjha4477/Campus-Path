# CampusPath

A verified college-first student community platform built with Express, Vite, React 19, Drizzle ORM, PostgreSQL, Firebase Auth, and Google Cloud Storage.

## Environment Configuration

Copy `.env.example` to `.env` (never commit `.env`) and configure:

- `DATABASE_URL` (Neon PostgreSQL connection string)
- `GCS_BUCKET` (private Google Cloud Storage bucket for post attachments)
- `PORT` (defaults to `3000`) and `NODE_ENV`
- `BOOTSTRAP_ADMIN_EMAIL` (optional initial admin bootstrap)

## Development

```bash
npm run dev
```

To populate sample development data in a non-production database:

```bash
npm run seed
```

`npm run seed` refuses to run when `NODE_ENV=production` unless `--force` is explicitly passed (`npm run seed -- --force`).

## Production Mode

Build the frontend bundle first, then start the Express server in production mode (serving only `dist/` and `dist/index.html` without loading Vite):

```bash
npm run build
npm start
```

`npm start` sets `NODE_ENV=production` and runs `tsx server.ts`.
