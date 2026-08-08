import { readFile, readdir } from 'node:fs/promises';
import { extname, join } from 'node:path';

const roots = ['src', 'public'];
const textExt = new Set(['.astro', '.html', '.js', '.mjs', '.ts', '.css', '.json', '.txt', '.xml', '.webmanifest']);
const files = [];
async function walk(dir) {
  for (const entry of await readdir(dir, { withFileTypes: true })) {
    const full = join(dir, entry.name);
    if (entry.isDirectory()) await walk(full);
    else if (textExt.has(extname(entry.name)) || entry.name.startsWith('.')) files.push(full);
  }
}
for (const root of roots) await walk(root);

const rules = [
  { name: 'inline event handler', re: /\son(?:click|load|error|mouseover|focus|submit)\s*=/i },
  { name: 'javascript URL', re: /javascript\s*:/i },
  { name: 'private key marker', re: /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/ },
  { name: 'AWS access key', re: /AKIA[0-9A-Z]{16}/ },
  { name: 'generic secret assignment', re: /(?:api[_-]?key|secret|token|password)\s*[:=]\s*['\"][A-Za-z0-9_\-]{20,}['\"]/i },
  { name: 'dangerous DOM HTML assignment', re: /\.innerHTML\s*=/ },
  { name: 'document.write', re: /document\.write\s*\(/ },
  { name: 'eval', re: /\beval\s*\(/ },
  { name: 'new Function', re: /new\s+Function\s*\(/ },
  { name: 'insecure asset/navigation URL', re: /(?:href|src)\s*=\s*['\"]http:\/\//i },
  { name: 'remote script', re: /<script[^>]+src\s*=\s*['\"]https?:\/\//i },
  { name: 'remote stylesheet', re: /<link[^>]+href\s*=\s*['\"]https?:\/\//i },
  { name: 'iframe', re: /<iframe\b/i },
  { name: 'form action', re: /<form\b[^>]+\baction\s*=/i },
];

let failures = 0;
for (const file of files) {
  const text = await readFile(file, 'utf8');
  for (const rule of rules) {
    if (rule.re.test(text)) {
      console.error(`[security-gate] ${rule.name}: ${file}`);
      failures += 1;
    }
  }
  for (const match of text.matchAll(/<a\b[^>]*target=["']_blank["'][^>]*>/gi)) {
    if (!/rel=["'][^"']*(?:noreferrer|noopener)[^"']*["']/i.test(match[0])) {
      console.error(`[security-gate] target=_blank without noopener/noreferrer: ${file}`);
      failures += 1;
    }
  }
}

if (failures) {
  console.error(`[security-gate] failed with ${failures} finding(s)`);
  process.exit(1);
}
console.log(`[security-gate] passed across ${files.length} source/public files`);
