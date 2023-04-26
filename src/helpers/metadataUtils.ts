import { decrypt } from "@toruslabs/eccrypto";
import BN from "bn.js";

import { ServerEciesData } from "../interfaces";

export function convertMetadataToNonce(params: { message?: string }) {
  if (!params || !params.message) {
    return new BN(0);
  }
  return new BN(params.message, 16);
}

export async function decryptNodeData(eciesData: ServerEciesData, ciphertextHex: string, privKey: Buffer): Promise<Buffer> {
  const metadata = {
    ephemPublicKey: Buffer.from(eciesData.ephemPublicKey, "hex"),
    iv: Buffer.from(eciesData.iv, "hex"),
    mac: Buffer.from(eciesData.mac, "hex"),
    // mode: Buffer.from(latestKey.Metadata.mode, "hex"),
  };
  const decryptedSigBuffer = await decrypt(privKey, {
    ...metadata,
    ciphertext: Buffer.from(ciphertextHex, "hex"),
  });
  return decryptedSigBuffer;
}
