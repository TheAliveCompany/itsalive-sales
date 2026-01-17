#!/usr/bin/env node

import chalk from 'chalk';
import ora from 'ora';
import prompts from 'prompts';
import readline from 'readline';
import { exec } from 'child_process';
import { glob } from 'glob';
import { readFile, writeFile, mkdir } from 'fs/promises';
import { existsSync } from 'fs';
import { join } from 'path';

function openUrl(url) {
  const cmd = process.platform === 'darwin' ? 'open' :
              process.platform === 'win32' ? 'start' : 'xdg-open';
  exec(`${cmd} ${url}`);
}

async function createStarterSite(subdomain) {
  const frontendDir = join(process.cwd(), 'frontend');
  if (!existsSync(frontendDir)) {
    await mkdir(frontendDir, { recursive: true });
  }

  const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${subdomain}.itsalive.co</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      color: #fff;
    }
    .container {
      text-align: center;
      padding: 2rem;
    }
    h1 {
      font-size: 2.5rem;
      margin-bottom: 1rem;
      background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
      background-clip: text;
    }
    p {
      color: #888;
      font-size: 1.1rem;
    }
  </style>
</head>
<body>
  <div class="container">
    <h1>${subdomain}.itsalive.co</h1>
    <p>Coming soon</p>
  </div>
</body>
</html>`;

  await writeFile(join(frontendDir, 'index.html'), html);
  return 'frontend';
}

const API_URL = 'https://api.itsalive.co';
const CONFIG_FILE = '.itsalive';

async function checkSubdomain(subdomain, email) {
  try {
    const res = await fetch(`${API_URL}/check-subdomain`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ subdomain, email }),
    });
    const data = await res.json();
    return data.available;
  } catch (e) {
    // If check fails, let them proceed and handle error during deploy
    return true;
  }
}

// Parse CLI flags
function parseArgs() {
  const args = process.argv.slice(2);
  const flags = {};

  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--dir' || args[i] === '-d') {
      flags.dir = args[i + 1];
      i++;
    } else if (args[i] === '--help' || args[i] === '-h') {
      console.log(`
Usage: npx itsalive-co [options]

Options:
  -d, --dir <folder>  Folder to deploy (overrides saved config)
  -h, --help          Show this help message
`);
      process.exit(0);
    }
  }

  return flags;
}

function promptSubdomain(initial = '') {
  return new Promise((resolve) => {
    const suffix = chalk.dim('.itsalive.co');
    const suffixLen = 12; // length of '.itsalive.co'
    let value = initial;
    let error = '';

    const rl = readline.createInterface({
      input: process.stdin,
      output: process.stdout,
    });

    const render = () => {
      readline.clearLine(process.stdout, 0);
      readline.cursorTo(process.stdout, 0);
      if (error) {
        process.stdout.write(chalk.red(`? `) + chalk.bold('Subdomain: ') + `${value} ${suffix}\n  ${chalk.red(error)}`);
        readline.moveCursor(process.stdout, 0, -1);
        readline.cursorTo(process.stdout, 13 + value.length);
      } else {
        process.stdout.write(chalk.cyan('? ') + chalk.bold('Subdomain: ') + value + ' ' + suffix);
        readline.cursorTo(process.stdout, 13 + value.length);
      }
    };

    const validate = (v) => {
      if (!v) return 'Subdomain is required';
      if (!/^[a-z0-9-]+$/.test(v)) {
        return 'Use only lowercase letters, numbers, and hyphens';
      }
      if (v.length < 3 || v.length > 30) {
        return 'Must be 3-30 characters';
      }
      return '';
    };

    process.stdin.setRawMode(true);
    process.stdin.resume();
    render();

    const onData = (key) => {
      const char = key.toString();

      if (char === '\r' || char === '\n') {
        // Enter pressed
        error = validate(value);
        if (!error) {
          // Move up one line, clear it, write final result
          process.stdout.write('\x1b[A\x1b[2K' + chalk.green('✔ ') + chalk.bold('Subdomain: ') + chalk.cyan(value) + chalk.dim('.itsalive.co') + '\n');
          process.stdin.setRawMode(false);
          process.stdin.off('data', onData);
          rl.close();
          resolve(value);
        } else {
          render();
        }
      } else if (char === '\x03') {
        // Ctrl+C
        console.log('\n\nDeployment cancelled.');
        process.exit(0);
      } else if (char === '\x7f' || char === '\b') {
        // Backspace
        value = value.slice(0, -1);
        error = '';
        render();
      } else if (char >= ' ' && char <= '~') {
        // Printable character - convert to lowercase
        value += char.toLowerCase();
        error = '';
        render();
      }
    };

    process.stdin.on('data', onData);
  });
}

async function main() {
  const flags = parseArgs();

  console.log(chalk.bold('\n🚀 itsalive.co\n'));

  // Check for existing config (progressive deployment)
  const configPath = join(process.cwd(), CONFIG_FILE);
  let config = null;
  let publishDir = flags.dir || '.';

  // Validate --dir flag if provided
  if (flags.dir && !existsSync(join(process.cwd(), flags.dir))) {
    console.error(chalk.red(`Directory "${flags.dir}" does not exist`));
    process.exit(1);
  }

  if (existsSync(configPath)) {
    try {
      const configData = await readFile(configPath, 'utf-8');
      const parsed = JSON.parse(configData);
      // Only use config if it has a valid deployToken (completed setup)
      if (parsed.deployToken) {
        config = parsed;
        // CLI flag overrides saved config
        if (!flags.dir) {
          publishDir = config.publishDir || '.';
        }
      }
    } catch (e) {
      // Invalid config, will do fresh deploy
    }
  }

  // First deploy - gather info before scanning files
  if (!config) {
    // Get subdomain with custom readline for proper cursor positioning
    let subdomain = await promptSubdomain();

    // Get email
    const emailResponse = await prompts({
      type: 'text',
      name: 'email',
      message: 'Email:',
      validate: (value) => {
        if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value)) {
          return 'Enter a valid email address';
        }
        return true;
      },
    });

    if (!emailResponse.email) {
      console.log('\nCancelled.');
      process.exit(0);
    }

    // Only prompt for directory if not provided via --dir flag
    if (!flags.dir) {
      // Check for common frontend directory patterns
      const frontendDirs = [
        'frontend',
        'src/frontend',
        'client',
        'src/client',
        'public',
        'dist',
        'build',
        'www',
        'web',
      ];
      const foundDir = frontendDirs.find(dir => existsSync(join(process.cwd(), dir)));

      // Only ask if we found a likely frontend folder
      if (foundDir) {
        const dirResponse = await prompts({
          type: 'text',
          name: 'publishDir',
          message: 'Folder to deploy:',
          initial: foundDir,
          validate: (value) => {
            const fullPath = join(process.cwd(), value);
            if (!existsSync(fullPath)) {
              return `Directory "${value}" does not exist`;
            }
            return true;
          },
        });

        if (!dirResponse.publishDir) {
          console.log('\nCancelled.');
          process.exit(0);
        }

        publishDir = dirResponse.publishDir;
      } else {
        publishDir = '.';
      }
    }

    // Check subdomain availability before proceeding
    let available = await checkSubdomain(subdomain, emailResponse.email);
    while (!available) {
      // Suggest alternatives
      const suggestions = [
        `${subdomain}${Math.floor(Math.random() * 100)}`,
        `${subdomain}-app`,
        `my-${subdomain}`,
      ];

      console.log(chalk.yellow(`\n😅 Oops! ${subdomain}.itsalive.co is taken.\n`));
      console.log(chalk.dim(`   Try one of these, or make up your own:\n`));
      suggestions.forEach(s => console.log(chalk.dim(`   • ${s}.itsalive.co`)));
      console.log('');

      subdomain = await promptSubdomain(subdomain);
      available = await checkSubdomain(subdomain, emailResponse.email);
    }

    // Store for later
    config = {
      _pending: true,
      subdomain,
      email: emailResponse.email,
      publishDir,
    };
  }

  // Find files to deploy
  const searchPath = join(process.cwd(), publishDir);

  const files = await glob('**/*', {
    cwd: searchPath,
    ignore: [
      'node_modules/**',
      '.git/**',
      '.env*',
      '*.log',
      '.DS_Store',
      'CLAUDE.md',
      'ITSALIVE.md',
      '.itsalive',
    ],
    nodir: true,
  });

  // Check for index.html (only warn, don't block)
  const hasIndex = files.some(f => f === 'index.html' || f.endsWith('/index.html'));
  if (files.length > 0 && !hasIndex) {
    console.log(chalk.yellow('\n⚠ No index.html found\n'));
  }

  try {
    if (config.deployToken) {
      // Progressive deploy - use existing token
      await pushDeploy(config, files, publishDir);
    } else if (files.length === 0) {
      // First deploy with no files - create starter site
      console.log(chalk.dim('\nCreating starter site...\n'));
      publishDir = await createStarterSite(config.subdomain);
      config.publishDir = publishDir;

      // Get the starter file
      const starterFiles = ['index.html'];

      // Deploy the starter site
      config = await firstDeploy(starterFiles, publishDir, config.subdomain, config.email);
      config.publishDir = publishDir;
      await writeFile(configPath, JSON.stringify(config, null, 2));
      await writeItsaliveMd(config.domain, publishDir);

      const url = `https://${config.domain}`;
      console.log(chalk.green.bold(`\n✨ https://${config.domain}\n`));
      console.log(chalk.dim(`   Start vibing with Claude!\n`));

      const { open } = await prompts({
        type: 'confirm',
        name: 'open',
        message: 'Open in browser?',
        initial: true,
      });
      if (open) openUrl(url);
      return;
    } else {
      // First deploy with files - need email verification
      config = await firstDeploy(files, publishDir, config.subdomain, config.email);
      config.publishDir = publishDir;
      await writeFile(configPath, JSON.stringify(config, null, 2));
    }

    // Write/update ITSALIVE.md (in project root, not publish dir)
    await writeItsaliveMd(config.domain, publishDir);

    // Success!
    const url = `https://${config.domain}`;
    console.log(chalk.green.bold(`\n✨ https://${config.domain}\n`));

    const { open } = await prompts({
      type: 'confirm',
      name: 'open',
      message: 'Open in browser?',
      initial: true,
    });
    if (open) openUrl(url);

  } catch (error) {
    console.error(chalk.red('\nDeployment failed:'), error.message);
    process.exit(1);
  }
}

async function firstDeploy(files, publishDir, subdomain, email) {
  console.log(chalk.cyan('\n📧 Check your email to verify...\n'));

  const initRes = await fetch(`${API_URL}/deploy/init`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ subdomain, email, files }),
  });

  const initData = await initRes.json();

  if (initData.error) {
    throw new Error(initData.error);
  }

  const deployId = initData.deploy_id;
  const spinner = ora('Waiting for you...').start();

  let verified = false;
  while (!verified) {
    await sleep(2000);
    const statusRes = await fetch(`${API_URL}/deploy/${deployId}/status`);
    const statusData = await statusRes.json();
    if (statusData.error) {
      spinner.fail(statusData.error);
      process.exit(1);
    }
    verified = statusData.verified;
  }

  spinner.succeed('Verified!');

  // Upload files
  await uploadFiles(files, `${API_URL}/deploy/${deployId}/upload`, null, publishDir);

  // Finalize deployment
  const finalizeRes = await fetch(`${API_URL}/deploy/${deployId}/finalize`, {
    method: 'POST',
  });

  const finalizeData = await finalizeRes.json();

  if (finalizeData.error) {
    throw new Error(finalizeData.error);
  }

  return {
    subdomain: finalizeData.subdomain,
    domain: `${finalizeData.subdomain}.itsalive.co`,
    email: finalizeData.email,
    deployToken: finalizeData.deployToken,
  };
}

async function pushDeploy(config, files, publishDir) {
  const pushRes = await fetch(`${API_URL}/push`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ deployToken: config.deployToken, files }),
  });

  const pushData = await pushRes.json();

  if (pushData.error) {
    // Check if it's an auth error or something else
    if (pushData.error.includes('token') || pushData.error.includes('auth') || pushData.error.includes('Invalid')) {
      console.log(chalk.yellow('\nToken expired. Run npx itsalive-co to re-authenticate.\n'));
      const configPath = join(process.cwd(), CONFIG_FILE);
      await writeFile(configPath, '{}');
    } else {
      console.log(chalk.red(`\nError: ${pushData.error}\n`));
    }
    process.exit(1);
  }

  // Update config with latest domain from API
  config.subdomain = pushData.subdomain;
  config.domain = pushData.domain;

  // Upload files
  await uploadFiles(files, `${API_URL}/push/upload`, config.deployToken, publishDir);

  return config;
}

async function uploadFiles(files, baseUrl, deployToken = null, publishDir = '.') {
  const total = files.length;
  let uploaded = 0;

  const renderProgress = () => {
    const pct = Math.round((uploaded / total) * 100);
    const filled = Math.round(pct / 5);
    const bar = '█'.repeat(filled) + '░'.repeat(20 - filled);
    return `Uploading ${bar} ${uploaded}/${total}`;
  };

  const spinner = ora(renderProgress()).start();

  // Upload files in parallel (batches of 10)
  const batchSize = 10;
  for (let i = 0; i < files.length; i += batchSize) {
    const batch = files.slice(i, i + batchSize);
    await Promise.all(batch.map(async (file) => {
      const filePath = join(process.cwd(), publishDir, file);
      const content = await readFile(filePath);
      let uploadUrl = `${baseUrl}?file=${encodeURIComponent(file)}`;
      if (deployToken) {
        uploadUrl += `&token=${encodeURIComponent(deployToken)}`;
      }

      await fetch(uploadUrl, {
        method: 'PUT',
        body: content,
        headers: {
          'Content-Type': getContentType(file),
        },
      });
      uploaded++;
      spinner.text = renderProgress();
    }));
  }

  spinner.succeed(`Uploaded ${total} files`);
}

async function writeItsaliveMd(domain, publishDir = '.') {
  const itsaliveMdPath = join(process.cwd(), 'ITSALIVE.md');
  const claudeMdPath = join(process.cwd(), 'CLAUDE.md');
  const referenceLine = 'See ITSALIVE.md for itsalive.co deployment and API documentation.';

  const publishDirNote = publishDir === '.'
    ? 'The entire project directory is deployed.'
    : `Only the \`${publishDir}/\` directory is deployed.`;

  // Fetch template from API (allows dynamic updates without CLI version bump)
  let templateContent = '';
  try {
    const res = await fetch(`${API_URL}/docs/itsalive-md`);
    if (res.ok) {
      templateContent = await res.text();
    }
  } catch (e) {
    // Fall through to fallback
  }

  // Fallback if API unavailable
  if (!templateContent) {
    templateContent = `## Authentication

### Login
\\\`\\\`\\\`javascript
const res = await fetch('https://api.itsalive.co/auth/login', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  credentials: 'include',
  body: JSON.stringify({ email: userEmail })
});
\\\`\\\`\\\`

### Check if logged in
\\\`\\\`\\\`javascript
const res = await fetch('https://api.itsalive.co/auth/me', { credentials: 'include' });
if (res.ok) { const { user } = await res.json(); }
\\\`\\\`\\\`

### Logout
\\\`\\\`\\\`javascript
await fetch('https://api.itsalive.co/auth/logout', { method: 'POST', credentials: 'include' });
\\\`\\\`\\\`

## Database

\\\`\\\`\\\`javascript
// Save (requires login)
await fetch('https://api.itsalive.co/db/{collection}/{id}', {
  method: 'PUT',
  headers: { 'Content-Type': 'application/json' },
  credentials: 'include',
  body: JSON.stringify({ ... })
});

// Get
const res = await fetch('https://api.itsalive.co/db/{collection}/{id}', { credentials: 'include' });

// List
const { items } = await fetch('https://api.itsalive.co/db/{collection}', { credentials: 'include' }).then(r => r.json());

// Delete (must be creator)
await fetch('https://api.itsalive.co/db/{collection}/{id}', { method: 'DELETE', credentials: 'include' });
\\\`\\\`\\\`

## User-Private Data

\\\`\\\`\\\`javascript
// Save
await fetch('https://api.itsalive.co/me/{key}', {
  method: 'PUT',
  headers: { 'Content-Type': 'application/json' },
  credentials: 'include',
  body: JSON.stringify({ ... })
});

// Get
const res = await fetch('https://api.itsalive.co/me/{key}', { credentials: 'include' });
\\\`\\\`\\\``;
  }

  // Build final content with header
  const itsaliveContent = `<!--
  DO NOT EDIT THIS FILE
  This file is automatically generated by itsalive.co and will be overwritten on each deploy.
  Add your own instructions to CLAUDE.md instead.
-->

# itsalive.co Integration

This app is deployed to https://${domain}

${publishDirNote}

## Deploying Updates

Run \`npx itsalive-co\` to deploy changes. No email verification needed after the first deploy.

${templateContent}
`;

  await writeFile(itsaliveMdPath, itsaliveContent);

  // Check CLAUDE.md for reference line
  if (existsSync(claudeMdPath)) {
    const claudeContent = await readFile(claudeMdPath, 'utf-8');
    if (!claudeContent.includes('ITSALIVE.md')) {
      // Add reference line at the top
      await writeFile(claudeMdPath, referenceLine + '\n\n' + claudeContent);
    }
  } else {
    // Create CLAUDE.md with just the reference
    await writeFile(claudeMdPath, referenceLine + '\n');
  }
}

function getContentType(path) {
  const ext = path.split('.').pop().toLowerCase();
  const types = {
    html: 'text/html',
    css: 'text/css',
    js: 'application/javascript',
    mjs: 'application/javascript',
    json: 'application/json',
    png: 'image/png',
    jpg: 'image/jpeg',
    jpeg: 'image/jpeg',
    gif: 'image/gif',
    svg: 'image/svg+xml',
    ico: 'image/x-icon',
    woff: 'font/woff',
    woff2: 'font/woff2',
    ttf: 'font/ttf',
    eot: 'application/vnd.ms-fontobject',
    webp: 'image/webp',
    mp4: 'video/mp4',
    webm: 'video/webm',
    mp3: 'audio/mpeg',
    wav: 'audio/wav',
    pdf: 'application/pdf',
    xml: 'application/xml',
    txt: 'text/plain',
    md: 'text/markdown',
  };
  return types[ext] || 'application/octet-stream';
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

main().catch(console.error);
