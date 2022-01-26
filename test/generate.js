var jwt = require("jsonwebtoken")
var jwkPrivKey = {
  "kty": "EC",
  "d": "YTl-2o5FkiY8pI_usMzxpDjeKgQXsL67rzF5EVq3CWM",
  "use": "sig",
  "crv": "P-256",
  "kid": "OaDIjzPPtHjTMq_0vcN5Np8QFZdGu8OsEfOMJuEIbKA",
  "x": "p4sxTq_901z0K4HaH3T7mrBffiq-R2NButNAbzYr5B4",
  "y": "GKOmjD5oIXiT-yB7DfGLoNj-DxFAALid8crbBoYXPW8",
  "alg": "ES256"
}

var jwkPubKeySet = 

{
  "keys": [
    {
      "kty": "EC",
      "use": "sig",
      "crv": "P-256",
      "kid": "OaDIjzPPtHjTMq_0vcN5Np8QFZdGu8OsEfOMJuEIbKA",
      "x": "p4sxTq_901z0K4HaH3T7mrBffiq-R2NButNAbzYr5B4",
      "y": "GKOmjD5oIXiT-yB7DfGLoNj-DxFAALid8crbBoYXPW8",
      "alg": "ES256"
    }
  ]
}

var privKey = `-----BEGIN PRIVATE KEY-----
MEECAQAwEwYHKoZIzj0CAQYIKoZIzj0DAQcEJzAlAgEBBCBhOX7ajkWSJjykj+6w
zPGkON4qBBewvruvMXkRWrcJYw==
-----END PRIVATE KEY-----`

export const generateIdToken = (email, alg) => {
  const iat = Math.floor(Date.now() / 1000);
  const payload = {
    iss: "torus-key-test",
    aud: "torus-key-test",
    name: email,
    email,
    scope: "email",
    iat,
    eat: iat + 120,
  };

  const algo = {
    expiresIn: 120,
    algorithm: alg,
  };

  return jwt.sign(payload, privKey, algo);
};

