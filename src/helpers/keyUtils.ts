import { INodePub } from "@toruslabs/constants";
import { Ecies, encrypt } from "@toruslabs/eccrypto";
import BN from "bn.js";
import { curve, ec as EC } from "elliptic";
import { keccak256 as keccakHash } from "ethereum-cryptography/keccak";
import stringify from "json-stable-stringify";

import { ImportedShare, KeyType } from "../interfaces";
import { encParamsBufToHex } from "./common";
import { generateRandomPolynomial } from "./langrangeInterpolatePoly";
import { generateNonceMetadataParams } from "./metadataUtils";

export function keccak256(a: Buffer): string {
  const hash = Buffer.from(keccakHash(a)).toString("hex");
  return `0x${hash}`;
}

export const generatePrivateKey = (ecCurve: EC, buf: typeof Buffer): Buffer => {
  return ecCurve.genKeyPair().getPrivate().toArrayLike(buf, "le", 32);
};

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

export function generateAddressFromPrivKey(ecCurve: EC, privateKey: BN): string {
  const key = ecCurve.keyFromPrivate(privateKey.toString("hex", 64), "hex");
  const publicKey = key.getPublic().encode("hex", false).slice(2);
  const evmAddressLower = `0x${keccak256(Buffer.from(publicKey, "hex")).slice(64 - 38)}`;
  return toChecksumAddress(evmAddressLower);
}

export function generateAddressFromPubKey(ecCurve: EC, publicKeyX: BN, publicKeyY: BN): string {
  const key = ecCurve.keyFromPublic({ x: publicKeyX.toString("hex", 64), y: publicKeyY.toString("hex", 64) });
  const publicKey = key.getPublic().encode("hex", false).slice(2);
  const evmAddressLower = `0x${keccak256(Buffer.from(publicKey, "hex")).slice(64 - 38)}`;
  return toChecksumAddress(evmAddressLower);
}

export function getPostboxKeyFrom1OutOf1(ecCurve: EC, privKey: string, nonce: string): string {
  const privKeyBN = new BN(privKey, 16);
  const nonceBN = new BN(nonce, 16);
  return privKeyBN.sub(nonceBN).umod(ecCurve.curve.n).toString("hex");
}

export function derivePubKey(ecCurve: EC, sk: BN): curve.base.BasePoint {
  const skHex = sk.toString(16, 64);
  return ecCurve.keyFromPrivate(skHex).getPublic();
}

export const encryptionEC = new EC("secp256k1");

export const generateShares = async (
  ecCurve: EC,
  keyType: KeyType,
  serverTimeOffset: number,
  nodeIndexes: number[],
  nodePubkeys: INodePub[],
  privKey: string
) => {
  const key = ecCurve.keyFromPrivate(privKey.padStart(64, "0"), "hex");

  const threshold = ~~(nodePubkeys.length / 2) + 1;
  const degree = threshold - 1;
  const nodeIndexesBn: BN[] = [];

  for (const nodeIndex of nodeIndexes) {
    nodeIndexesBn.push(new BN(nodeIndex));
  }
  const privKeyBn = key.getPrivate();
  const randomNonce = new BN(generatePrivateKey(ecCurve, Buffer));
  const oAuthKey = privKeyBn.sub(randomNonce).umod(ecCurve.curve.n);
  const oAuthPubKey = ecCurve.keyFromPrivate(oAuthKey.toString("hex").padStart(64, "0")).getPublic();
  const poly = generateRandomPolynomial(ecCurve, degree, oAuthKey);
  const shares = poly.generateShares(nodeIndexesBn);
  const nonceParams = generateNonceMetadataParams(ecCurve, serverTimeOffset, "getOrSetNonce", oAuthKey, keyType, randomNonce);
  const nonceData = Buffer.from(stringify(nonceParams.set_data), "utf8").toString("base64");
  const sharesData: ImportedShare[] = [];
  const encPromises: Promise<Ecies>[] = [];
  for (let i = 0; i < nodeIndexesBn.length; i++) {
    const shareJson = shares[nodeIndexesBn[i].toString("hex", 64)].toJSON() as Record<string, string>;
    if (!nodePubkeys[i]) {
      throw new Error(`Missing node pub key for node index: ${nodeIndexesBn[i].toString("hex", 64)}`);
    }
    const nodePubKey = encryptionEC.keyFromPublic({ x: nodePubkeys[i].X, y: nodePubkeys[i].Y });
    encPromises.push(
      encrypt(Buffer.from(nodePubKey.getPublic().encodeCompressed("hex"), "hex"), Buffer.from(shareJson.share.padStart(64, "0"), "hex"))
    );
  }
  const encShares = await Promise.all(encPromises);
  for (let i = 0; i < nodeIndexesBn.length; i++) {
    const shareJson = shares[nodeIndexesBn[i].toString("hex", 64)].toJSON() as Record<string, string>;
    const encParams = encShares[i];
    const encParamsMetadata = encParamsBufToHex(encParams);
    const shareData: ImportedShare = {
      pub_key_x: oAuthPubKey.getX().toString("hex", 64),
      pub_key_y: oAuthPubKey.getY().toString("hex", 64),
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
