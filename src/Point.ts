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
}

export default Point;
