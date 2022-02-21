const defaultConfig = {
  cjsBundled: true,
  bundledDeps: ['@toruslabs/eccrypto', 'elliptic', 'web3-utils', 'bn.js'],
  analyzerMode: 'disabled',
}

module.exports = defaultConfig
// TODO: Import this file into packages which need it
