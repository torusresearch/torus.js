import commonjs from '@rollup/plugin-commonjs'
import json from '@rollup/plugin-json'
import resolve from '@rollup/plugin-node-resolve'
import babel from 'rollup-plugin-babel'
import nodebns from 'rollup-plugin-node-builtins'
import nodeglob from 'rollup-plugin-node-globals'
import { terser } from 'rollup-plugin-terser'

import pkg from './package.json'

const pkgName = 'torusUtils'

export default [
  // browser-friendly UMD build - polyfilled with corejs 3
  {
    input: 'index.js',
    output: [
      {
        name: pkgName,
        file: `dist/${pkgName}.polyfill.umd.js`,
        format: 'umd',
      },
      {
        name: pkgName,
        file: `dist/${pkgName}.polyfill.umd.min.js`,
        format: 'umd',
      },
    ],
    plugins: [
      nodebns(),
      json(),
      babel({ runtimeHelpers: true }),
      resolve({ preferBuiltins: false, browser: true }), // so Rollup can find dependencies
      commonjs(), // so Rollup can convert dependencies to an ES module
      nodeglob({ baseDir: false, dirname: false, filename: false, global: true, process: false }),
      terser({ include: '*.min.*' }),
    ],
  },
  // browser-friendly UMD build - not polyfilled
  {
    input: 'index.js',
    output: [
      {
        name: pkgName,
        file: `dist/${pkgName}.umd.js`,
        format: 'umd',
      },
      {
        name: pkgName,
        file: `dist/${pkgName}.umd.min.js`,
        format: 'umd',
      },
    ],
    plugins: [
      nodebns(),
      json(),
      babel({ runtimeHelpers: true, plugins: ['@babel/transform-runtime'] }),
      resolve({ preferBuiltins: false, browser: true }), // so Rollup can find dependencies
      commonjs(), // so Rollup can convert dependencies to an ES module
      nodeglob({ baseDir: false, dirname: false, filename: false, global: true, process: false }),
      terser({ include: '*.min.*' }),
    ],
  },

  // CommonJS (for Node) and ES module (for bundlers) build.
  // (We could have three entries in the configuration array
  // instead of two, but it's quicker to generate multiple
  // builds from a single configuration where possible, using
  // an array for the `output` option, where we can specify
  // `file` and `format` for each target)
  {
    input: 'index.js',
    external: [
      ...Object.keys(pkg.dependencies),
      'elliptic/lib/elliptic/ec',
      '@babel/runtime/helpers/toConsumableArray',
      '@babel/runtime/regenerator',
      '@babel/runtime/helpers/asyncToGenerator',
      '@babel/runtime/helpers/classCallCheck',
      '@babel/runtime/helpers/createClass',
      '@babel/runtime/helpers/defineProperty',
    ],
    output: [
      { file: pkg.main, format: 'cjs' },
      { file: pkg.module, format: 'es' },
    ],
    plugins: [
      json(),
      babel({ runtimeHelpers: true, plugins: ['@babel/transform-runtime'] }),
      nodebns(),
      nodeglob({ baseDir: false, dirname: false, filename: false, global: true, process: false }),
      terser({ include: '*.min.*' }),
    ],
  },
]
