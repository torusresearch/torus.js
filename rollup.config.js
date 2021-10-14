import babel from '@rollup/plugin-babel'
import path from 'path'
import sourceMaps from 'rollup-plugin-sourcemaps'

import pkg from './package.json'

const pkgName = 'torusUtils'

export default [
  {
    input: path.resolve('.', 'src', 'index.js'),
    external: [...Object.keys(pkg.dependencies), /^(@babel\/runtime)/i],
    output: [{ file: `dist/${pkgName}.esm.js`, format: 'es', sourcemap: true }],
    plugins: [babel({ babelHelpers: 'runtime' }), sourceMaps()],
  },
]
