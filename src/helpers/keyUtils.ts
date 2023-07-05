import BN from "bn.js";
import { ec } from "elliptic";
import { keccak256 as keccakHash } from "ethereum-cryptography/keccak";

import log from "../loglevel";

export function keccak256(a: Buffer): string {
  const hash = Buffer.from(keccakHash(a)).toString("hex");
  return `0x${hash}`;
}

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

export function generateAddressFromPrivKey(ecCurve: ec, privateKey: BN): string {
  const key = ecCurve.keyFromPrivate(privateKey.toString("hex", 64), "hex");
  const publicKey = key.getPublic().encode("hex", false).slice(2);
  log.info(publicKey, "public key");
  const evmAddressLower = `0x${keccak256(Buffer.from(publicKey, "hex")).slice(64 - 38)}`;
  return toChecksumAddress(evmAddressLower);
}

export function generateAddressFromPubKey(ecCurve: ec, publicKeyX: BN, publicKeyY: BN): string {
  const key = ecCurve.keyFromPublic({ x: publicKeyX.toString("hex", 64), y: publicKeyY.toString("hex", 64) });
  const publicKey = key.getPublic().encode("hex", false).slice(2);
  log.info(key.getPublic().encode("hex", false), "public key");
  const evmAddressLower = `0x${keccak256(Buffer.from(publicKey, "hex")).slice(64 - 38)}`;
  return toChecksumAddress(evmAddressLower);
}

export function getPostboxKeyFrom1OutOf1(ecCurve: ec, privKey: string, nonce: string): string {
  const privKeyBN = new BN(privKey, 16);
  const nonceBN = new BN(nonce, 16);
  return privKeyBN.sub(nonceBN).umod(ecCurve.curve.n).toString("hex");
}
