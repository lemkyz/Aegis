import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const readmeTarget = path.join(root, 'src', 'data', 'README.snapshot.md');
const readmeEmbedTarget = path.join(root, 'src', 'data', 'README.embed.md');
const metaTarget = path.join(root, 'src', 'data', 'github.snapshot.json');
const readmeUrl = 'https://raw.githubusercontent.com/lemkyz/Aegis/main/README.md';
const repoUrl = 'https://api.github.com/repos/lemkyz/Aegis';
const commitsUrl = 'https://api.github.com/repos/lemkyz/Aegis/commits?per_page=1';
const headers = { 'user-agent': 'aegis-public-site-build', accept: 'application/vnd.github+json' };

function sanitizeReadmeForEmbed(markdown) {
  // The README is our own public repository content, but the website still treats
  // build-time content as untrusted input. Keep the Markdown readable while
  // stripping constructs that should never become active website UI.
  return markdown
    .replace(/<script\b[\s\S]*?<\/script>/gi, '')
    .replace(/<style\b[\s\S]*?<\/style>/gi, '')
    .replace(/<(?:iframe|object|embed|form|input|button|textarea|select|option|link|meta)\b[^>]*>/gi, '')
    .replace(/<\/(?:iframe|object|embed|form|button|textarea|select|option)>/gi, '')
    .replace(/\son[a-z]+\s*=\s*(?:"[^"]*"|'[^']*'|[^\s>]+)/gi, '')
    .replace(/javascript\s*:/gi, '')
    .replace(/data\s*:\s*text\/html/gi, '')
    .replace(/<h1([^>]*)>/gi, '<h2 class="repo-readme-title"$1>')
    .replace(/<\/h1>/gi, '</h2>')
    .replace(/^#\s+/gm, '## ');
}

async function timedFetch(url, timeoutMs = 6000) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try { return await fetch(url, { signal: controller.signal, headers }); }
  finally { clearTimeout(timer); }
}

try {
  const response = await timedFetch(readmeUrl);
  if (!response.ok) throw new Error(`GitHub README returned ${response.status}`);
  const text = await response.text();
  if (text.length > 300_000) throw new Error('README payload exceeds the 300 KB build-time limit');
  if (!text.includes('Trust infrastructure for software agents')) throw new Error('Unexpected README payload');
  fs.writeFileSync(readmeTarget, text);
  fs.writeFileSync(readmeEmbedTarget, sanitizeReadmeForEmbed(text));
  console.log('github snapshot: refreshed README.md + embed copy');
} catch (error) {
  if (!fs.existsSync(readmeTarget)) throw error;
  console.warn(`github snapshot: using checked-in README fallback (${error.message})`);
}

try {
  const repoResponse = await timedFetch(repoUrl);
  if (!repoResponse.ok) throw new Error(`GitHub repo API returned ${repoResponse.status}`);
  const repo = await repoResponse.json();
  if (repo.full_name !== 'lemkyz/Aegis') throw new Error('Unexpected repository metadata payload');
  let commits = null;
  try {
    const commitResponse = await timedFetch(commitsUrl);
    if (commitResponse.ok) {
      const link = commitResponse.headers.get('link') || '';
      const match = link.match(/[?&]page=(\d+)>; rel="last"/);
      commits = match ? Number(match[1]) : 1;
    }
  } catch { /* preserve fallback if commit-count lookup fails */ }
  const previous = fs.existsSync(metaTarget) ? JSON.parse(fs.readFileSync(metaTarget, 'utf8')) : {};
  const meta = {
    full_name: repo.full_name || 'lemkyz/Aegis',
    default_branch: repo.default_branch || 'main',
    visibility: repo.visibility || (repo.private ? 'private' : 'public'),
    commits: commits ?? previous.commits ?? null,
    stars: repo.stargazers_count ?? previous.stars ?? null,
    forks: repo.forks_count ?? previous.forks ?? null,
    watchers: repo.subscribers_count ?? previous.watchers ?? null,
    snapshot_note: 'refreshed at production build from the public GitHub API'
  };
  fs.writeFileSync(metaTarget, `${JSON.stringify(meta, null, 2)}\n`);
  console.log('github snapshot: refreshed repository metadata');
} catch (error) {
  if (!fs.existsSync(metaTarget)) throw error;
  console.warn(`github snapshot: using checked-in metadata fallback (${error.message})`);
}
