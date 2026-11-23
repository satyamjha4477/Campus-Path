import 'dotenv/config';
import { drizzle } from 'drizzle-orm/node-postgres';
import { Pool } from 'pg';
import * as schema from './schema.ts';

declare global {
  var _postgresPool: Pool | undefined;
}

export const createPool = () => {
  if (!global._postgresPool) {
    if (!process.env.DATABASE_URL) {
      console.error(
        'DATABASE_URL environment variable is not set. Database queries will fail until DATABASE_URL is configured.'
      );
    }

    global._postgresPool = new Pool({
      connectionString: process.env.DATABASE_URL,
      ssl: { rejectUnauthorized: true },
      max: 5,
      idleTimeoutMillis: 30000,
      connectionTimeoutMillis: 20000,
    });

    global._postgresPool.on('error', (err) => {
      console.error('Unexpected error on idle SQL pool client:', err);
    });
  }
  return global._postgresPool;
};

export const pool = createPool();

export const db = drizzle(pool, { schema });
