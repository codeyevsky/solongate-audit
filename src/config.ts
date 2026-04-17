import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'node:fs';
import { resolve, join } from 'node:path';
import { homedir } from 'node:os';

const CONFIG_DIR = resolve(homedir(), '.solongate-audit');
const CONFIG_FILE = join(CONFIG_DIR, 'config.json');

interface Config {
  customDirs: string[];
}

function ensureConfigDir(): void {
  if (!existsSync(CONFIG_DIR)) {
    mkdirSync(CONFIG_DIR, { recursive: true });
  }
}

export function loadConfig(): Config {
  if (!existsSync(CONFIG_FILE)) {
    return { customDirs: [] };
  }
  try {
    return JSON.parse(readFileSync(CONFIG_FILE, 'utf-8'));
  } catch {
    return { customDirs: [] };
  }
}

function saveConfig(config: Config): void {
  ensureConfigDir();
  writeFileSync(CONFIG_FILE, JSON.stringify(config, null, 2));
}

export function addDir(dir: string): void {
  const absDir = resolve(dir);
  const config = loadConfig();
  if (config.customDirs.includes(absDir)) {
    console.log(`  Already added: ${absDir}`);
    return;
  }
  if (!existsSync(absDir)) {
    console.log(`  Warning: directory does not exist: ${absDir}`);
    console.log(`  Adding anyway — it may appear later.\n`);
  }
  config.customDirs.push(absDir);
  saveConfig(config);
  console.log(`  Added: ${absDir}`);
  console.log(`  Total custom dirs: ${config.customDirs.length}\n`);
}

export function removeDir(dir: string): void {
  const absDir = resolve(dir);
  const config = loadConfig();
  const idx = config.customDirs.indexOf(absDir);
  if (idx === -1) {
    // Try partial match
    const match = config.customDirs.find((d) => d.includes(dir));
    if (match) {
      config.customDirs.splice(config.customDirs.indexOf(match), 1);
      saveConfig(config);
      console.log(`  Removed: ${match}`);
      console.log(`  Remaining: ${config.customDirs.length}\n`);
      return;
    }
    console.log(`  Not found: ${absDir}`);
    console.log(`  Use --list-dirs to see saved directories.\n`);
    return;
  }
  config.customDirs.splice(idx, 1);
  saveConfig(config);
  console.log(`  Removed: ${absDir}`);
  console.log(`  Remaining: ${config.customDirs.length}\n`);
}

export function listDirs(): void {
  const config = loadConfig();
  const home = homedir();

  console.log('\n  Default log directories:');
  console.log(`    Claude Code  → ${resolve(home, '.claude', 'projects')}`);
  console.log(`    Gemini CLI   → ${resolve(home, '.gemini', 'tmp')}`);
  console.log(`    OpenClaw     → ${resolve(home, '.openclaw', 'agents', 'main', 'sessions')}`);

  if (config.customDirs.length === 0) {
    console.log('\n  Custom directories: (none)');
  } else {
    console.log(`\n  Custom directories (${config.customDirs.length}):`);
    for (const d of config.customDirs) {
      const exists = existsSync(d);
      console.log(`    ${exists ? '+' : '-'} ${d}${exists ? '' : ' (not found)'}`);
    }
  }

  console.log(`\n  Config: ${CONFIG_FILE}\n`);
}

export function searchLogs(): void {
  const home = homedir();
  const found: string[] = [];

  console.log('\n  Searching for AI tool logs...\n');

  // Known default locations
  const defaults = [
    { name: 'Claude Code', path: resolve(home, '.claude', 'projects') },
    { name: 'Gemini CLI', path: resolve(home, '.gemini', 'tmp') },
    { name: 'OpenClaw', path: resolve(home, '.openclaw', 'agents', 'main', 'sessions') },
  ];

  for (const d of defaults) {
    if (existsSync(d.path)) {
      console.log(`  Found ${d.name}: ${d.path}`);
      found.push(d.path);
    }
  }

  // Search other user profiles (Windows)
  if (process.platform === 'win32') {
    const usersDir = resolve(home, '..');
    try {
      const { readdirSync, statSync } = require('node:fs');
      for (const user of readdirSync(usersDir)) {
        const userHome = join(usersDir, user);
        if (userHome === home) continue;
        try {
          if (!statSync(userHome).isDirectory()) continue;
        } catch { continue; }

        const otherPaths = [
          { name: `Claude Code (${user})`, path: resolve(userHome, '.claude', 'projects') },
          { name: `Gemini CLI (${user})`, path: resolve(userHome, '.gemini', 'tmp') },
          { name: `OpenClaw (${user})`, path: resolve(userHome, '.openclaw', 'agents', 'main', 'sessions') },
        ];
        for (const d of otherPaths) {
          if (existsSync(d.path)) {
            console.log(`  Found ${d.name}: ${d.path}`);
            found.push(d.path);
          }
        }
      }
    } catch {}
  }

  // Search common Linux/macOS paths
  if (process.platform !== 'win32') {
    try {
      const { readdirSync } = require('node:fs');
      for (const baseDir of ['/home', '/Users']) {
        if (!existsSync(baseDir)) continue;
        for (const user of readdirSync(baseDir)) {
          const userHome = join(baseDir, user);
          if (userHome === home) continue;

          const otherPaths = [
            { name: `Claude Code (${user})`, path: resolve(userHome, '.claude', 'projects') },
            { name: `Gemini CLI (${user})`, path: resolve(userHome, '.gemini', 'tmp') },
            { name: `OpenClaw (${user})`, path: resolve(userHome, '.openclaw', 'agents', 'main', 'sessions') },
          ];
          for (const d of otherPaths) {
            try {
              if (existsSync(d.path)) {
                console.log(`  Found ${d.name}: ${d.path}`);
                found.push(d.path);
              }
            } catch {}
          }
        }
      }
    } catch {}
  }

  if (found.length === 0) {
    console.log('  No AI tool logs found.\n');
  } else {
    console.log(`\n  Found ${found.length} log location(s).`);
    console.log('  Default locations are scanned automatically.');
    console.log('  To add a non-default location: npx solongate-audit --add-dir <path>\n');
  }
}
