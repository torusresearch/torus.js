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

  encode(enc: string): Buffer {
    switch (enc) {
      case "arr":
        return Buffer.concat([Buffer.from("04", "hex"), Buffer.from(this.x.toString("hex"), "hex"), Buffer.from(this.y.toString("hex"), "hex")]);
      case "elliptic-compressed": {
        const key = this.ecCurve.keyFromPublic({ x: this.x.toString("hex", 64), y: this.y.toString("hex", 64) }, "hex");
        return Buffer.from(key.getPublic(true, "hex"));
      }
      default:
        throw new Error("encoding doesn't exist in Point");
    }
  }
}

export default Point;
