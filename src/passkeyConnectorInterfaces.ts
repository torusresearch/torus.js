import { TorusUtilsPasskeyExtraParams } from "./TorusUtilsExtraParams";

export type GetAuthMessageFromNodesParams = { endpoints: string[]; verifier: string; verifierId?: string; passkeyPubKey?: string };

export type PasskeyAuthData = {
  verifier: string;
  verifier_id: string;
  id_token: string;
  key_type: KeyType;
  node_signatures: string[];
} & TorusUtilsPasskeyExtraParams;

// passkey auth data is required only when relinking a existing passkey
export type LinkPasskeyParams = {
  endpoints: string[];
  passkeyPubKey: string;
  message: string;
  label: string;
  oAuthKeySignature: string;
  keyType: KeyType;
  passkeyAuthData?: PasskeyAuthData;
};

export type UnLinkPasskeyParams = {
  endpoints: string[];
  passkeyPubKey: string;
  message: string;
  oAuthKeySignature: string;
  keyType: KeyType;
};
export type ListLinkedPasskeysParams = {
  endpoints: string[];
  message: string;
  oAuthKeySignature: string;
  keyType: KeyType;
};

export type PasskeyListItem = { label: string; verifier: string; verifier_id: string; passkey_pub_key: string };
export type ListLinkedPasskeysResponse = {
  passkeys: PasskeyListItem[];
};
