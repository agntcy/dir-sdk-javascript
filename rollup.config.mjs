// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

import json from '@rollup/plugin-json';
import { readFileSync } from 'fs';
import typescript from 'rollup-plugin-typescript2';
import { nodeResolve } from '@rollup/plugin-node-resolve';

const pkg = JSON.parse(readFileSync(new URL('./package.json', import.meta.url), 'utf8'));

const rollupPlugins = [
  nodeResolve(),
  typescript({
    tsconfigOverride: {
      exclude: ['test/**'],
    },
  }),
  json({
    preferConst: true,
  }),
  fixBufEsmImportSpecifiers(),
];

/** Keep npm dependencies external so Rollup does not rewrite `this` in bundled deps. */
const externalPackages = [
  ...Object.keys(pkg.dependencies ?? {}),
  ...Object.keys(pkg.optionalDependencies ?? {}),
];

function isExternal(id) {
  if (id.startsWith('node:')) {
    return true;
  }
  if (id.startsWith('.') || id.startsWith('/') || id.startsWith('\0')) {
    return false;
  }
  return externalPackages.some((dep) => id === dep || id.startsWith(`${dep}/`));
}

/**
 * Node ESM requires explicit .js extensions for @buf protobuf subpath imports.
 */
function fixBufEsmImportSpecifiers() {
  return {
    name: 'fix-buf-esm-import-specifiers',
    renderChunk(code, chunk) {
      if (!chunk.fileName.endsWith('.mjs')) {
        return null;
      }
      const updated = code.replace(
        /from (['"])(@buf\/[^'"]+)(['"])/g,
        (_, quote, specifier, endQuote) =>
          specifier.endsWith('.js')
            ? `from ${quote}${specifier}${endQuote}`
            : `from ${quote}${specifier}.js${endQuote}`,
      );
      if (updated === code) {
        return null;
      }
      return { code: updated, map: null };
    },
  };
}

export default [
  // Cross ES module (dist/index.mjs)
  {
    input: 'src/index.ts',
    output: {
      file: pkg.exports['.']['import'],
      format: 'es',
      sourcemap: true,
    },
    plugins: rollupPlugins,
    external: isExternal,
  },

  // Cross CJS module (dist/index.cjs)
  {
    input: 'src/index.ts',
    output: {
      file: pkg.exports['.']['require'],
      format: 'cjs',
      sourcemap: true,
    },
    plugins: rollupPlugins,
    external: isExternal,
  },
];
