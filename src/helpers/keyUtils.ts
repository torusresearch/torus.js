import { bs58 } from "@toruslabs/bs58";
import { INodePub, KEY_TYPE } from "@toruslabs/constants";
import { Ecies, encrypt } from "@toruslabs/eccrypto";
import BN from "bn.js";
import { curve, ec as EC } from "elliptic";
import { keccak256 as keccakHash } from "ethereum-cryptography/keccak";
import { sha512 } from "ethereum-cryptography/sha512";
import stringify from "json-stable-stringify";
import log from "loglevel";

import { EncryptedSeed, ImportedShare, KeyType, PrivateKeyData } from "../interfaces";
import { encParamsBufToHex, generatePrivateKey, getKeyCurve, keccak256 } from "./common";
import { generateRandomPolynomial } from "./langrangeInterpolatePoly";
import { generateNonceMetadataParams, getSecpKeyFromEd25519 } from "./metadataUtils";

export function stripHexPrefix(str: string): string {
  return str.startsWith("0x") ? str.slice(2) : str;
}

export function toChecksumAddress(hexAddress: string): string {
  const address = stripHexPrefix(hexAddress).toLowerCase();

  const buf = Buffer.from(address, "utf8");
  const hash = Buffer.from(keccakHash(buf)).toString("hex");
  let ret = "0x";

  for (let i = 0; i < address.length; i++) {
    if (parseInt(hash[i], 16) >= 8) {
      ret += address[i].toUpperCase();
    } else {
      ret += address[i];
    }
  }

  return ret;
}

function adjustScalarBytes(bytes: Buffer): Buffer {
  // Section 5: For X25519, in order to decode 32 random bytes as an integer scalar,
  // set the three least significant bits of the first byte
  bytes[0] &= 248; // 0b1111_1000
  // and the most significant bit of the last to zero,
  bytes[31] &= 127; // 0b0111_1111
  // set the second most significant bit of the last byte to 1
  bytes[31] |= 64; // 0b0100_0000
  return bytes;
}

/** Convenience method that creates public key and other stuff. RFC8032 5.1.5 */
export function getEd25519ExtendedPublicKey(keyBuffer: Buffer): {
  scalar: BN;
  point: curve.base.BasePoint;
} {
  const ed25519Curve = getKeyCurve(KEY_TYPE.ED25519);
  const len = 32;
  const G = ed25519Curve.g;
  const N = ed25519Curve.n;

  if (keyBuffer.length !== 32) {
    log.error("Invalid seed for ed25519 key derivation", keyBuffer.length);
    throw new Error("Invalid seed for ed25519 key derivation");
  }
  // Hash private key with curve's hash function to produce uniformingly random input
  // Check byte lengths: ensure(64, h(ensure(32, key)))
  const hashed = sha512(keyBuffer);
  if (hashed.length !== 64) {
    throw new Error("Invalid hash length for ed25519 seed");
  }
  const head = new BN(adjustScalarBytes(Buffer.from(hashed.slice(0, len))), "le");
  const scalar = new BN(head.umod(N), "le"); // The actual private scalar
  const point = G.mul(scalar) as curve.base.BasePoint; // Point on Edwards curve aka public key
  return { scalar, point };
}

export function encodeEd25519Point(point: curve.base.BasePoint) {
  const ed25519Curve = getKeyCurve(KEY_TYPE.ED25519);

  const encodingLength = Math.ceil(ed25519Curve.n.bitLength() / 8);
  const enc = point.getY().toArrayLike(Buffer, "le", encodingLength);
  enc[encodingLength - 1] |= point.getX().isOdd() ? 0x80 : 0;
  return enc;
}

export const generateEd25519KeyData = async (ed25519Seed: Buffer): Promise<PrivateKeyData> => {
  const ed25519Curve = getKeyCurve(KEY_TYPE.ED25519);

  const finalEd25519Key = getEd25519ExtendedPublicKey(ed25519Seed);
  const encryptionKey = getSecpKeyFromEd25519(finalEd25519Key.scalar);
  const encryptedSeed = await encrypt(Buffer.from(encryptionKey.point.encodeCompressed("hex"), "hex"), ed25519Seed);
  const encData: EncryptedSeed = {
    enc_text: encryptedSeed.ciphertext.toString("hex"),
    metadata: encParamsBufToHex(encryptedSeed),
    public_key: encodeEd25519Point(finalEd25519Key.point).toString("hex"),
  };

  const encDataBase64 = Buffer.from(JSON.stringify(encData), "utf-8").toString("base64");
  const metadataPrivNonce = ed25519Curve.genKeyPair().getPrivate();
  const oauthKey = finalEd25519Key.scalar.sub(metadataPrivNonce).umod(ed25519Curve.n);
  const oauthKeyPair = ed25519Curve.keyFromPrivate(oauthKey.toArrayLike(Buffer));
  const metadataSigningKey = getSecpKeyFromEd25519(oauthKeyPair.getPrivate());
  return {
    oAuthKeyScalar: oauthKeyPair.getPrivate(),
    oAuthPubX: oauthKeyPair.getPublic().getX(),
    oAuthPubY: oauthKeyPair.getPublic().getY(),
    SigningPubX: metadataSigningKey.point.getX(),
    SigningPubY: metadataSigningKey.point.getY(),
    metadataNonce: metadataPrivNonce,
    metadataSigningKey: metadataSigningKey.scalar,
    encryptedSeed: encDataBase64,
    finalUserPubKeyPoint: finalEd25519Key.point,
  };
};

export const generateSecp256k1KeyData = async (scalarBuffer: Buffer): Promise<PrivateKeyData> => {
  const secp256k1Curve = getKeyCurve(KEY_TYPE.SECP256K1);

  const scalar = new BN(scalarBuffer);
  const randomNonce = new BN(generatePrivateKey(secp256k1Curve, Buffer));
  const oAuthKey = scalar.sub(randomNonce).umod(secp256k1Curve.n);
  const oAuthKeyPair = secp256k1Curve.keyFromPrivate(oAuthKey.toArrayLike(Buffer));
  const oAuthPubKey = oAuthKeyPair.getPublic();

  const finalUserKeyPair = secp256k1Curve.keyFromPrivate(scalar.toString("hex", 64), "hex");

  return {
    oAuthKeyScalar: oAuthKeyPair.getPrivate(),
    oAuthPubX: oAuthPubKey.getX(),
    oAuthPubY: oAuthPubKey.getY(),
    SigningPubX: oAuthPubKey.getX(),
    SigningPubY: oAuthPubKey.getY(),
    metadataNonce: randomNonce,
    encryptedSeed: "",
    metadataSigningKey: oAuthKeyPair.getPrivate(),
    finalUserPubKeyPoint: finalUserKeyPair.getPublic(),
  };
};

function generateAddressFromEcKey(keyType: KeyType, key: EC.KeyPair): string {
  if (keyType === KEY_TYPE.SECP256K1) {
    const publicKey = key.getPublic().encode("hex", false).slice(2);
    const evmAddressLower = `0x${keccak256(Buffer.from(publicKey, "hex")).slice(64 - 38)}`;
    return toChecksumAddress(evmAddressLower);
  } else if (keyType === KEY_TYPE.ED25519) {
    const publicKey = encodeEd25519Point(key.getPublic());
    const address = bs58.encode(publicKey);
    return address;
  }
  throw new Error(`Invalid keyType: ${keyType}`);
}

export function generateAddressFromPrivKey(keyType: KeyType, privateKey: BN): string {
  const ecCurve = getKeyCurve(keyType);
  const key = ecCurve.keyFromPrivate(privateKey.toString("hex", 64), "hex");
  return generateAddressFromEcKey(keyType, key);
}

export function generateAddressFromPubKey(keyType: KeyType, publicKeyX: BN, publicKeyY: BN): string {
  const ecCurve = getKeyCurve(keyType);
  const key = ecCurve.keyFromPublic({ x: publicKeyX.toString("hex", 64), y: publicKeyY.toString("hex", 64) });
  return generateAddressFromEcKey(keyType, key);
}

export function getPostboxKeyFrom1OutOf1(ecCurve: EC, privKey: string, nonce: string): string {
  const privKeyBN = new BN(privKey, 16);
  const nonceBN = new BN(nonce, 16);
  return privKeyBN.sub(nonceBN).umod(ecCurve.n).toString("hex");
}

export function derivePubKey(ecCurve: EC, sk: BN): curve.base.BasePoint {
  const skHex = sk.toString(16, 64);
  return ecCurve.keyFromPrivate(skHex, "hex").getPublic();
}

export const getEncryptionEC = (): EC => {
  return new EC("secp256k1");
};

export const generateShares = async (
  ecCurve: EC,
  keyType: KeyType,
  serverTimeOffset: number,
  nodeIndexes: number[],
  nodePubkeys: INodePub[],
  privKey: Buffer
) => {
  const keyData = keyType === KEY_TYPE.ED25519 ? await generateEd25519KeyData(privKey) : await generateSecp256k1KeyData(privKey);
  const { metadataNonce, oAuthKeyScalar: oAuthKey, encryptedSeed, metadataSigningKey } = keyData;
  const threshold = ~~(nodePubkeys.length / 2) + 1;
  const degree = threshold - 1;
  const nodeIndexesBn: BN[] = [];

  for (const nodeIndex of nodeIndexes) {
    nodeIndexesBn.push(new BN(nodeIndex));
  }
  const oAuthPubKey = ecCurve.keyFromPrivate(oAuthKey.toString("hex", 64), "hex").getPublic();
  const poly = generateRandomPolynomial(ecCurve, degree, oAuthKey);
  const shares = poly.generateShares(nodeIndexesBn);
  const nonceParams = generateNonceMetadataParams(serverTimeOffset, "getOrSetNonce", metadataSigningKey, keyType, metadataNonce, encryptedSeed);
  const nonceData = Buffer.from(stringify(nonceParams.set_data), "utf8").toString("base64");
  const sharesData: ImportedShare[] = [];
  const encPromises: Promise<Ecies>[] = [];
  for (let i = 0; i < nodeIndexesBn.length; i++) {
    const shareJson = shares[nodeIndexesBn[i].toString("hex", 64)].toJSON() as Record<string, string>;
    if (!nodePubkeys[i]) {
      throw new Error(`Missing node pub key for node index: ${nodeIndexesBn[i].toString("hex", 64)}`);
    }
    const nodePubKey = getEncryptionEC().keyFromPublic({ x: nodePubkeys[i].X, y: nodePubkeys[i].Y });
    encPromises.push(
      encrypt(Buffer.from(nodePubKey.getPublic().encodeCompressed("hex"), "hex"), Buffer.from(shareJson.share.padStart(64, "0"), "hex"))
    );
  }
  const encShares = await Promise.all(encPromises);
  for (let i = 0; i < nodeIndexesBn.length; i += 1) {
    const shareJson = shares[nodeIndexesBn[i].toString("hex", 64)].toJSON() as Record<string, string>;
    const encParams = encShares[i];
    const encParamsMetadata = encParamsBufToHex(encParams);
    const shareData: ImportedShare = {
      encrypted_seed: keyData.encryptedSeed,
      final_user_point: keyData.finalUserPubKeyPoint,
      oauth_pub_key_x: oAuthPubKey.getX().toString("hex"),
      oauth_pub_key_y: oAuthPubKey.getY().toString("hex"),
      signing_pub_key_x: keyData.SigningPubX.toString("hex"),
      signing_pub_key_y: keyData.SigningPubY.toString("hex"),
      encrypted_share: encParamsMetadata.ciphertext,
      encrypted_share_metadata: encParamsMetadata,
      node_index: Number.parseInt(shareJson.shareIndex, 16),
      key_type: keyType,
      nonce_data: nonceData,
      nonce_signature: nonceParams.signature,
    };
    sharesData.push(shareData);
  }

  return sharesData;
};
