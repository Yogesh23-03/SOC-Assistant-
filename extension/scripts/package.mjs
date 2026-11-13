import { readdir, readFile, writeFile } from 'node:fs/promises';
import { join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';
import { zipSync } from 'fflate';
const root = new URL('../dist/', import.meta.url);
const files = {};
async function collect(directory) {
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) await collect(path);
    else files[relative(fileURLToPath(root), path).replaceAll('\\', '/')] = new Uint8Array(await readFile(path));
  }
}
await collect(fileURLToPath(root));
await writeFile(new URL('../soc-assistant-extension.zip', import.meta.url), zipSync(files));
console.log('Packaged soc-assistant-extension.zip');
