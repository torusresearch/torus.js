import { decrypt } from "@toruslabs/eccrypto";
import BN from "bn.js";

import { EciesHex } from "../interfaces";
import { encParamsHexToBuf } from "./common";

export function convertMetadataToNonce(params: { message?: string }) {
  if (!params || !params.message) {
    return new BN(0);
  }
  return new BN(params.message, 16);
}

export async function decryptNodeData(eciesData: EciesHex, ciphertextHex: string, privKey: Buffer): Promise<Buffer> {
  const metadata = encParamsHexToBuf(eciesData);
  const decryptedSigBuffer = await decrypt(privKey, {
    ...metadata,
    ciphertext: Buffer.from(ciphertextHex, "hex"),
  });
  return decryptedSigBuffer;
}
