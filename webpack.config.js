const path = require('path')
const webpack = require('webpack')
const ESLintPlugin = require('eslint-webpack-plugin')

const pkg = require('./package.json')

const pkgName = 'torusUtils'
const libraryName = pkgName.charAt(0).toUpperCase() + pkgName.slice(1)

const packagesToInclude = ['@toruslabs/eccrypto', 'elliptic', 'web3-utils', 'bn.js']

const { NODE_ENV = 'production' } = process.env

const baseConfig = {
  mode: NODE_ENV,
  devtool: NODE_ENV === 'production' ? false : 'source-map',
  entry: './index.js',
  target: 'web',
  output: {
    path: path.resolve(__dirname, 'dist'),
    library: libraryName,
    libraryExport: 'default',
  },
  resolve: {
    alias: {
      'bn.js': path.resolve(__dirname, 'node_modules/bn.js'),
      lodash: path.resolve(__dirname, 'node_modules/lodash'),
      'js-sha3': path.resolve(__dirname, 'node_modules/js-sha3'),
    },
  },
  module: {
    rules: [],
  },
  node: {
    vm: 'empty',
  },
}

const optimization = {
  optimization: {
    minimize: false,
  },
}

const babelLoaderWithPolyfills = {
  test: /\.m?js$/,
  exclude: /(node_modules|bower_components)/,
  use: {
    loader: 'babel-loader',
  },
}

const babelLoader = { ...babelLoaderWithPolyfills, use: { loader: 'babel-loader', options: { plugins: ['@babel/transform-runtime'] } } }

const umdPolyfilledConfig = {
  ...baseConfig,
  output: {
    ...baseConfig.output,
    filename: `${pkgName}.polyfill.umd.min.js`,
    libraryTarget: 'umd',
  },
  module: {
    rules: [babelLoaderWithPolyfills],
  },
}

const umdConfig = {
  ...baseConfig,
  output: {
    ...baseConfig.output,
    filename: `${pkgName}.umd.min.js`,
    libraryTarget: 'umd',
  },
  module: {
    rules: [babelLoader],
  },
}

const cjsConfig = {
  ...baseConfig,
  output: {
    ...baseConfig.output,
    filename: `${pkgName}.cjs.js`,
    libraryTarget: 'commonjs2',
  },
  module: {
    rules: [babelLoader],
  },
  plugins: [
    new ESLintPlugin({
      files: 'src',
    }),
  ],
  externals: [...Object.keys(pkg.dependencies), /^(@babel\/runtime)/i],
  node: {
    ...baseConfig.node,
    Buffer: false,
  },
}

const cjsBundledConfig = {
  ...baseConfig,
  output: {
    ...baseConfig.output,
    filename: `${pkgName}-bundled.cjs.js`,
    libraryTarget: 'commonjs2',
  },
  module: {
    rules: [babelLoader],
  },
  externals: [...Object.keys(pkg.dependencies).filter((x) => !packagesToInclude.includes(x)), /^(@babel\/runtime)/i],
}

const nodeConfig = {
  ...baseConfig,
  ...optimization,
  output: {
    ...baseConfig.output,
    filename: `${pkgName}-node.js`,
    libraryTarget: 'commonjs2',
  },
  module: {
    rules: [babelLoader],
  },
  externals: [...Object.keys(pkg.dependencies), /^(@babel\/runtime)/i],
  target: 'node',
  plugins: [
    new webpack.ProvidePlugin({
      fetch: ['node-fetch', 'default'],
    }),
  ],
}

module.exports = [umdPolyfilledConfig, umdConfig, cjsConfig, cjsBundledConfig, nodeConfig]
// module.exports = [cjsConfig]

// V5
// experiments: {
//   outputModule: true
// }

// node: {
//   global: true,
// },
// resolve: {
//   alias: { crypto: 'crypto-browserify', stream: 'stream-browserify', vm: 'vm-browserify' },
//   aliasFields: ['browser'],
// },
