import dotenv from 'dotenv'
import jwt from 'jsonwebtoken'

dotenv.config({ path: `.env.${process.env.NODE_ENV}` })
const JWT_PRIV = process.env.TEST_VERIFIER_KEY
const jwtPrivateKey = JWT_PRIV.replace(/\\n/gm, '\n')

export const generateIdToken = (email, alg) => {
  const iat = Math.floor(Date.now() / 1000)
  const payload = {
    iss: 'torus-key-test',
    aud: 'torus-key-test',
    name: email,
    email,
    scope: 'email',
    iat,
    eat: iat + 3600,
  }

  const algo = {
    expiresIn: '1h',
    algorithm: alg,
  }

  return jwt.sign(payload, jwtPrivateKey, algo)
}
