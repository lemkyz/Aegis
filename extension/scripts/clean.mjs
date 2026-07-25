import {
  readdir,
  rm,
} from "node:fs/promises";
import {
  join,
} from "node:path";

const root = process.cwd();

await rm(
  join(root, "dist"),
  {
    recursive: true,
    force: true,
  },
);

const entries = await readdir(
  root,
  {
    withFileTypes: true,
  },
);

for (const entry of entries) {
  if (
    entry.isFile()
    && entry.name.endsWith(".vsix")
  ) {
    await rm(
      join(root, entry.name),
      {
        force: true,
      },
    );
  }
}

console.log(
  "Aegis extension build artifacts cleaned.",
);
