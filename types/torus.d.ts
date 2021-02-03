import BN from 'bn.js'

declare class Torus {
    constructor(options?: TorusCtorOptions);
    static setAPIKey(apiKey: string): void;
    static setEmbedHost(embedHost: string): void;
    retrieveShares(endpoints: string[], indexes: Number[], verifier: 'google' | 'facebook' | 'twitch' | 'reddit' | 'discord' | 'jwt' | string, verifierParams: VerifierParams, idToken: string, extraParams?: extraParams): Promise<ShareResponse>;
    lagrangeInterpolation(shares: BN[], nodeIndex: BN[]): BN;
    generateAddressFromPrivKey(privateKey: BN): string;
    getPublicAddress(endpoints: string[], torusNodePubs: TorusNodePub[], verifierArgs: VerifierArgs, isExtended: boolean): Promise<string | TorusPublicKey>;
}

export as namespace TorusUtils;

export = Torus;
interface extraParams {
    [key: string]: unknown;
}

interface TorusCtorOptions {
    enableLogging?: boolean;
    metadataHost?: string;
    allowHost?: string;
}

interface TorusPublicKey extends TorusNodePub {
    address: string;
    metadataNonce: BN;
}

interface TorusNodePub {
    X: string;
    Y: string;
}

interface ShareResponse {
    ethAddress: string;
    privKey: string;
    metadataNonce: BN;
}

interface VerifierArgs {
    verifier: 'google' | 'facebook' | 'twitch' | 'reddit' | 'discord' | 'jwt' | string;
    verifierId: string;
}

interface VerifierParams {
    verifier_id: string;
}