const path = require('path')

module.exports = {
  mode: 'production',
  entry: './index.js',
  target: 'web',
  output: {
    path: path.resolve(__dirname, 'dist'),
    filename: 'bundle.js',
    library: 'torusUtils',
    // libraryExport: 'default',
    libraryTarget: 'umd',
  },
  module: {
    rules: [
      {
        test: /\.m?js$/,
        exclude: /(node_modules|bower_components)/,
        use: {
          loader: 'babel-loader',
          options: {
            // presets: ['@babel/preset-env']
          },
        },
      },
    ],
  },
  // node: {
  //   global: true,
  // },
  // resolve: {
  //   alias: { crypto: 'crypto-browserify', stream: 'stream-browserify', vm: 'vm-browserify', Buffer: 'buffer' },
  //   aliasFields: ['browser']
  // },
  optimization: {
    minimize: false,
  },
}
