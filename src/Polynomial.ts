import BN from "bn.js";
import { ec as EC } from "elliptic";

import { BNString } from "./interfaces";
import Share from "./Share";

export type ShareMap = {
  [x: string]: Share;
};

class Polynomial {
  polynomial: BN[];

  ecCurve: EC;

  constructor(polynomial: BN[], ecCurve: EC) {
    this.polynomial = polynomial;
    this.ecCurve = ecCurve;
  }

  getThreshold(): number {
    return this.polynomial.length;
  }

  polyEval(x: BNString): BN {
    const tmpX = new BN(x, "hex");
    let xi = new BN(tmpX);
    let sum = new BN(0);
    sum = sum.add(this.polynomial[0]);
    for (let i = 1; i < this.polynomial.length; i += 1) {
      const tmp = xi.mul(this.polynomial[i]);
      sum = sum.add(tmp);
      sum = sum.umod(this.ecCurve.curve.n);
      xi = xi.mul(new BN(tmpX));
      xi = xi.umod(this.ecCurve.curve.n);
    }
    return sum;
  }

  generateShares(shareIndexes: BNString[]): ShareMap {
    const newShareIndexes = shareIndexes.map((index) => {
      if (typeof index === "number") {
        return new BN(index);
      }
      if (index instanceof BN) {
        return index;
      }
      if (typeof index === "string") {
        return new BN(index, "hex");
      }
      return index;
    });

    const shares: ShareMap = {};
    for (let x = 0; x < newShareIndexes.length; x += 1) {
      shares[newShareIndexes[x].toString("hex", 64)] = new Share(newShareIndexes[x], this.polyEval(newShareIndexes[x]));
    }
    return shares;
  }
}

export default Polynomial;
