// import alias from '@rollup/plugin-alias'
import commonjs from '@rollup/plugin-commonjs'
import json from '@rollup/plugin-json'
import resolve from '@rollup/plugin-node-resolve'
import path from 'path'
import babel from 'rollup-plugin-babel'
import nodebns from 'rollup-plugin-node-builtins'
import nodeglob from 'rollup-plugin-node-globals'
import { terser } from 'rollup-plugin-terser'
import typescript2 from 'rollup-plugin-typescript2'
import ts from 'typescript'

// import pkg from './package.json'

const pkgName = 'torusUtils'

export default [
  // browser-friendly UMD build - polyfilled with corejs 3
  // {
  //   input: 'index.js',
  //   output: [
  //     {
  //       name: pkgName,
  //       file: `dist/${pkgName}.polyfill.umd.js`,
  //       format: 'umd',
  //     },
  //     {
  //       name: pkgName,
  //       file: `dist/${pkgName}.polyfill.umd.min.js`,
  //       format: 'umd',
  //     },
  //   ],
  //   plugins: [
  //     alias({
  //       entries: [{ find: 'elliptic', replacement: path.resolve(__dirname, 'includes/ellipticInterface') }],
  //     }),
  //     nodebns({ crypto: true }),
  //     json(),
  //     babel({ runtimeHelpers: true, exclude: 'node_modules/**' }),
  //     resolve({ preferBuiltins: false, browser: true }), // so Rollup can find dependencies
  //     commonjs({
  //       ignoreGlobal: true,
  //       include: [/node_modules/, /includes/],
  //       // namedExports: {
  //       //   // [path.resolve(__dirname, 'includes/elliptic')]: ['ec'],
  //       //   'includes/ellipticInterface': ['ec'],
  //       // },
  //     }), // so Rollup can convert dependencies to an ES module
  //     nodeglob({ baseDir: false, dirname: false, filename: false, global: true, process: true }),
  //     terser({ include: '*.min.*' }),
  //   ],
  // },
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
      // alias({
      //   entries: [{ find: 'elliptic', replacement: path.resolve(__dirname, 'includes/elliptic.js') }],
      // }),
      nodebns({ crypto: true }),
      json(),
      babel({ runtimeHelpers: true, plugins: ['@babel/transform-runtime'], exclude: 'node_modules/**' }),
      resolve({ preferBuiltins: false, browser: true }), // so Rollup can find dependencies
      commonjs({
        ignoreGlobal: true,
        include: [/node_modules/, /includes/],
        // namedExports: {
        //   elliptic: ['ec'],
        // },
      }), // so Rollup can convert dependencies to an ES module
      nodeglob({ baseDir: false, dirname: false, filename: false, global: true, process: true }),
      typescript2({
        tsconfig: path.join(__dirname, 'tsconfig.json'),
        typescript: ts, // ensure we're using the same typescript (3.x) for rollup as for regular builds etc
        tsconfigOverride: {
          compilerOptions: {
            module: 'esnext',
            stripInternal: true,
            emitDeclarationOnly: false,
            composite: false,
            declaration: false,
            declarationMap: false,
            sourceMap: true,
          },
        },
      }),
      terser({ include: '*.min.*' }),
    ],
  },
  // CommonJS (for Node) and ES module (for bundlers) build.
  // (We could have three entries in the configuration array
  // instead of two, but it's quicker to generate multiple
  // builds from a single configuration where possible, using
  // an array for the `output` option, where we can specify
  // `file` and `format` for each target)
  // {
  //   input: 'index.js',
  //   external: [
  //     ...Object.keys(pkg.dependencies).filter((x) => x !== 'eccrypto' && x !== 'elliptic'),
  //     '@babel/runtime/helpers/toConsumableArray',
  //     '@babel/runtime/regenerator',
  //     '@babel/runtime/helpers/asyncToGenerator',
  //     '@babel/runtime/helpers/classCallCheck',
  //     '@babel/runtime/helpers/createClass',
  //     '@babel/runtime/helpers/defineProperty',
  //     '@babel/runtime/helpers/typeof',
  //   ],
  //   output: [
  //     { file: pkg.main, format: 'cjs' },
  //     { file: pkg.module, format: 'es' },
  //   ],
  //   plugins: [
  //     alias({
  //       entries: [{ find: 'elliptic', replacement: path.resolve(__dirname, 'includes/elliptic.js') }],
  //     }),
  //     nodebns({ crypto: true }),
  //     json(),
  //     babel({ runtimeHelpers: true, plugins: ['@babel/transform-runtime'] }),
  //     resolve({ preferBuiltins: false, browser: true }),
  //     commonjs({
  //       ignoreGlobal: true,
  //       include: [/node_modules/, /includes/],
  //       namedExports: {
  //         elliptic: ['ec'],
  //       },
  //     }),
  //     nodeglob({ baseDir: false, dirname: false, filename: false, global: true, process: true }),
  //     terser({ include: '*.min.*' }),
  //   ],
  // },
]
