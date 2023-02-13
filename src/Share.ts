import BN from "bn.js";

import { BNString, StringifiedType } from "./interfaces";

class Share {
  share: BN;

  shareIndex: BN;

  constructor(shareIndex: BNString, share: BNString) {
    this.share = new BN(share, "hex");
    this.shareIndex = new BN(shareIndex, "hex");
  }

  static fromJSON(value: StringifiedType): Share {
    const { share, shareIndex } = value;
    return new Share(shareIndex as BNString, share as BNString);
  }

  toJSON(): StringifiedType {
    return {
      share: this.share.toString("hex"),
      shareIndex: this.shareIndex.toString("hex"),
    };
  }
}

export default Share;
