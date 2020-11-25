'use strict';

const builtins = require('rollup-plugin-node-builtins');
const rollJson = require('rollup-plugin-json');
const fs = require('fs');
const del = require('del');
const rollup = require('rollup');
const babel = require('rollup-plugin-babel');
const resolve = require('rollup-plugin-node-resolve');
const commonjs = require('rollup-plugin-commonjs');
const pkg = require('../package.json');

let promise = Promise.resolve();

// Clean up the output directory
promise = promise.then(() => del(['dist/*']));

// Compile source code into a distributable format with Babel
[ 'cjs'].forEach((format) => {
  promise = promise.then(() => rollup.rollup({
    input: 'src/index.js',
    // entry: 'src/index.js',
    // external: Object.keys(pkg.dependencies),
    resolve: {
      alias: {
        // replace native `scrypt` module with pure js `js-scrypt`
        "scrypt": "js-scrypt",

        // fix websocket require path
        // "websocket": path.resolve(__dirname, "../")
      }
    },
    plugins: [
      resolve(),
      rollJson(),
      builtins(),
      babel(Object.assign(pkg.babel, {
        babelrc: false,
        exclude: 'node_modules/**',
        externalHelpers: false,
        runtimeHelpers: true,
        presets: pkg.babel.env.production.presets,
      })),
      commonjs(),
    ],
  }))
    .then(bundle => bundle.write({
      file: `dist/${format === 'cjs' ? 'index' : `index.${format}`}.js`,
      format,
      sourceMap: false,
      name: format === 'umd' ? pkg.name : undefined,
    }));
});

// Copy package.json and LICENSE.txt
promise = promise.then(() => {
  delete pkg.private;
  delete pkg.devDependencies;
  delete pkg.scripts;
  delete pkg.eslintConfig;
  delete pkg.babel;
  fs.writeFileSync('dist/package.json', JSON.stringify(pkg, null, '  '), 'utf-8');
  fs.writeFileSync('dist/LICENSE.txt', fs.readFileSync('LICENSE.txt', 'utf-8'), 'utf-8');
});

promise.catch(err => console.error(err.stack)); // eslint-disable-line no-console
