import dotenv from 'dotenv';
import { ensureSeedData } from './seed.ts';

dotenv.config();

async function main() {
  const isProduction = process.env.NODE_ENV === 'production';
  const hasForce = process.argv.includes('--force');

  if (isProduction && !hasForce) {
    console.error(
      'Refusing to run database seed when NODE_ENV=production. Re-run with --force if you intentionally want to seed a production database.'
    );
    process.exit(1);
  }

  await ensureSeedData();
  console.log('CampusPath seed completed.');
  process.exit(0);
}

main().catch((err) => {
  console.error('CampusPath seed failed:', err);
  process.exit(1);
});
