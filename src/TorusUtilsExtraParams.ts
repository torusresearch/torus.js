export interface TorusUtilsExtraParams {
  nonce?: string; // farcaster

  message?: string; // farcaster

  signature?: string; // farcaster, passkey, webauthn

  clientDataJson?: string; // passkey, webauthn

  authenticatorData?: string; // passkey, webauhn

  publicKey?: string; // passkey, webauthn

  challenge?: string; // passkey, webauthn

  rpOrigin?: string; // passkey, webauthn

  rpId?: string; // passkey, webauthn

  session_token_exp_second?: number;

  timestamp?: number; // Signature
}
