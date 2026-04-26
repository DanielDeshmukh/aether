import fs from 'node:fs';
import path from 'node:path';

const rootDir = process.cwd();
const envPath = path.join(rootDir, '.env');
const examplePath = path.join(rootDir, '.env.example');

const requiredVars = [
  'SUPABASE_URL',
  'SUPABASE_SERVICE_ROLE_KEY',
  'DATABASE_URL',
  'FRONTEND_URL',
  'VITE_SUPABASE_URL',
  'VITE_SUPABASE_ANON_KEY',
];

const placeholderPatterns = [
  /^your_/i,
  /example/i,
  /changeme/i,
];

function parseEnvFile(contents) {
  const values = new Map();

  for (const rawLine of contents.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith('#')) {
      continue;
    }

    const separatorIndex = line.indexOf('=');
    if (separatorIndex === -1) {
      continue;
    }

    const key = line.slice(0, separatorIndex).trim();
    const value = line.slice(separatorIndex + 1).trim().replace(/^['"]|['"]$/g, '');
    values.set(key, value);
  }

  return values;
}

if (!fs.existsSync(envPath)) {
  console.error(`[env-check] Missing ${envPath}`);
  if (fs.existsSync(examplePath)) {
    console.error(`[env-check] Create it from ${examplePath} before running the stack.`);
  }
  process.exit(1);
}

const envValues = parseEnvFile(fs.readFileSync(envPath, 'utf8'));
const missingVars = [];

for (const key of requiredVars) {
  const value = envValues.get(key)?.trim() ?? '';
  const isPlaceholder = placeholderPatterns.some((pattern) => pattern.test(value));
  if (!value || isPlaceholder) {
    missingVars.push(key);
  }
}

if (missingVars.length > 0) {
  console.error('[env-check] The root .env file is not ready yet.');
  console.error(`[env-check] Fill in: ${missingVars.join(', ')}`);
  process.exit(1);
}

console.log('[env-check] Root .env looks ready. Launching AETHER stack...');
