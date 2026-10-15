// Finds the translation keys of the app: literal t(...) calls in the sources, the messages of ApiError made in the
// browser, and the English messages of SPA's API errors (fail(status, "code", "message") in backend/internal/app), which
// describeError translates by text.
import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';

export function sourceFiles(dir: string): string[] {
  return readdirSync(dir).flatMap((name) => {
    const path = join(dir, name);
    if (statSync(path).isDirectory()) return sourceFiles(path);
    return /\.tsx?$/.test(name) && !/\.test\.tsx?$/.test(name) ? [path] : [];
  });
}

/** Literal keys passed to t(…) (string or template literal without ${}). */
export function translationKeys(code: string): string[] {
  const keys: string[] = [];
  const re = /\bt\(\s*(?:'((?:[^'\\]|\\.)*)'|"((?:[^"\\]|\\.)*)"|`([^`$]*)`)/g;
  for (const m of code.matchAll(re)) keys.push((m[1] ?? m[2] ?? m[3]).replace(/\\(.)/g, '$1'));
  for (const m of code.matchAll(/new ApiError\(\d+, '[a-z_]+', '((?:[^'\\]|\\.)*)'/g)) keys.push(m[1]);
  return keys;
}

/** Whole-literal messages of the API errors (messages built with + are left in English). */
export function serverMessages(backendDir: string): string[] {
  if (!existsSync(backendDir)) return [];
  const out = new Set<string>();
  for (const f of readdirSync(backendDir).filter((n) => n.endsWith('.go') && !n.endsWith('_test.go'))) {
    const code = readFileSync(join(backendDir, f), 'utf8');
    for (const m of code.matchAll(/fail\(http\.\w+, "[a-z_]+", "((?:[^"\\]|\\.)*)"\)/g)) out.add(m[1].replace(/\\(.)/g, '$1'));
    for (const m of code.matchAll(/Message: "((?:[^"\\]|\\.)*)"/g)) out.add(m[1]);
  }
  return [...out];
}
