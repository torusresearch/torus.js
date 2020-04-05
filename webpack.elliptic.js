const path = require('path')

module.exports = {
  entry: {
    elliptic: path.resolve(__dirname, 'node_modules/elliptic/lib/elliptic.js'),
  },
  output: {
    filename: 'elliptic.js',
    library: 'elliptic',
    libraryExport: 'default',
    libraryTarget: 'commonjs2',
    path: path.resolve(__dirname, 'includes'),
  },
  mode: 'production',
  optimization: {
    minimize: false,
  },
}
