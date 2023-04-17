import BN from "bn.js";

export function convertMetadataToNonce(params: { message?: string }) {
  if (!params || !params.message) {
    return new BN(0);
  }
  return new BN(params.message, 16);
}
