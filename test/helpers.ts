import jwt, { Algorithm, Secret } from "jsonwebtoken";

export const generateIdToken = (alg: Algorithm, key: Secret, expiry: number, email: string, iss: String, aud: String, sub: String) => {
  const iat = Math.floor(Date.now() / 1000);
  const payload = {
    iss,
    aud,
    sub,
    name: email,
    email,
    scope: "email",
    iat,
    eat: iat + Math.round(expiry),
  };

  const algo = {
    expiresIn: Math.round(expiry),
    algorithm: alg,
  };

  return jwt.sign(payload, key, algo);
};
