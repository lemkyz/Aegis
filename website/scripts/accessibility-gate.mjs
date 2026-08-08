import { readFile, readdir } from 'node:fs/promises';
import { extname, join } from 'node:path';

const roots = ['src/pages', 'src/components'];
const files = [];
async function walk(dir) {
  for (const entry of await readdir(dir, { withFileTypes: true })) {
    const full = join(dir, entry.name);
    if (entry.isDirectory()) await walk(full);
    else if (extname(entry.name) === '.astro') files.push(full);
  }
}
for (const root of roots) await walk(root);

let failures = 0;
const fail = (message, file) => {
  console.error(`[a11y-gate] ${message}: ${file}`);
  failures += 1;
};

for (const file of files) {
  const text = await readFile(file, 'utf8');

  for (const img of text.matchAll(/<img\b[^>]*>/gi)) {
    if (!/\balt\s*=/.test(img[0])) fail('image missing alt attribute', file);
  }

  for (const button of text.matchAll(/<button\b[^>]*>/gi)) {
    if (!/\btype\s*=/.test(button[0]) && !/role=["']tab["']/.test(button[0])) {
      fail('button missing explicit type', file);
    }
  }

  for (const input of text.matchAll(/<(input|select|textarea)\b[^>]*\bid=["']([^"']+)["'][^>]*>/gi)) {
    const id = input[2];
    const labelRe = new RegExp(`<label[^>]+for=["']${id.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}["']`, 'i');
    if (!labelRe.test(text)) fail(`form control #${id} has no matching label`, file);
  }

  if (file.includes('/pages/') && !file.endsWith('404.astro')) {
    const h1Count = (text.match(/<h1\b/gi) || []).length;
    if (h1Count !== 1) fail(`page should contain exactly one h1 (found ${h1Count})`, file);
  }
}

if (failures) {
  console.error(`[a11y-gate] failed with ${failures} finding(s)`);
  process.exit(1);
}
console.log(`[a11y-gate] passed across ${files.length} Astro files`);
