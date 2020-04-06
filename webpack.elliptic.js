const path = require('path')

module.exports = {
  entry: {
    elliptic: path.resolve(__dirname, 'node_modules/elliptic/lib/elliptic/ec/index.js'),
  },
  output: {
    filename: 'elliptic.js',
    library: 'elliptic',
    libraryTarget: 'commonjs2',
    path: path.resolve(__dirname, 'includes'),
  },
  mode: 'production',
  optimization: {
    minimize: false,
  },
}
