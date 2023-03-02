import BN from "bn.js";
import { ec as EC } from "elliptic";

import { BNString } from "./interfaces";

class Point {
  x: BN;

  y: BN;

  ecCurve: EC;

  constructor(x: BNString, y: BNString, ecCurve: EC) {
    this.x = new BN(x, "hex");
    this.y = new BN(y, "hex");
    this.ecCurve = ecCurve;
  }

  // complies with EC and elliptic pub key types
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  encode(enc: string, params?: any): Buffer {
    switch (enc) {
      case "arr":
        return Buffer.concat([Buffer.from("0x04", "hex"), Buffer.from(this.x.toString("hex"), "hex"), Buffer.from(this.y.toString("hex"), "hex")]);
      case "elliptic-compressed": {
        // TODO: WHAT IS THIS.?
        let ec = params;
        ec = this.ecCurve;
        const key = ec.keyFromPublic({ x: this.x.toString("hex"), y: this.y.toString("hex") }, "hex");
        return Buffer.from(key.getPublic(true, "hex"));
      }
      default:
        throw new Error("encoding doesnt exist in Point");
    }
  }
}

export default Point;
