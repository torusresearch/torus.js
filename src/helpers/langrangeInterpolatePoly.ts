import { generatePrivate } from "@toruslabs/eccrypto";
import BN from "bn.js";
import { ec as EC } from "elliptic";

import Point from "../Point";
import Polynomial from "../Polynomial";
import Share from "../Share";

function generatePrivateExcludingIndexes(shareIndexes: BN[]): BN {
  const key = new BN(generatePrivate());
  if (shareIndexes.find((el) => el.eq(key))) {
    return generatePrivateExcludingIndexes(shareIndexes);
  }
  return key;
}
const generateEmptyBNArray = (length: number): BN[] => Array.from({ length }, () => new BN(0));

const denominator = (ecCurve: EC, i: number, innerPoints: Point[]) => {
  let result = new BN(1);
  const xi = innerPoints[i].x;
  for (let j = innerPoints.length - 1; j >= 0; j -= 1) {
    if (i !== j) {
      let tmp = new BN(xi);
      tmp = tmp.sub(innerPoints[j].x);
      tmp = tmp.umod(ecCurve.curve.n);
      result = result.mul(tmp);
      result = result.umod(ecCurve.curve.n);
    }
  }
  return result;
};

const interpolationPoly = (ecCurve: EC, i: number, innerPoints: Point[]): BN[] => {
  let coefficients = generateEmptyBNArray(innerPoints.length);
  const d = denominator(ecCurve, i, innerPoints);
  if (d.cmp(new BN(0)) === 0) {
    throw new Error("Denominator for interpolationPoly is 0");
  }
  coefficients[0] = d.invm(ecCurve.curve.n);
  for (let k = 0; k < innerPoints.length; k += 1) {
    const newCoefficients = generateEmptyBNArray(innerPoints.length);
    if (k !== i) {
      let j: number;
      if (k < i) {
        j = k + 1;
      } else {
        j = k;
      }
      j -= 1;
      for (; j >= 0; j -= 1) {
        newCoefficients[j + 1] = newCoefficients[j + 1].add(coefficients[j]).umod(ecCurve.curve.n);
        let tmp = new BN(innerPoints[k].x);
        tmp = tmp.mul(coefficients[j]).umod(ecCurve.curve.n);
        newCoefficients[j] = newCoefficients[j].sub(tmp).umod(ecCurve.curve.n);
      }
      coefficients = newCoefficients;
    }
  }
  return coefficients;
};

const pointSort = (innerPoints: Point[]): Point[] => {
  const pointArrClone = [...innerPoints];
  pointArrClone.sort((a, b) => a.x.cmp(b.x));
  return pointArrClone;
};

const lagrange = (ecCurve: EC, unsortedPoints: Point[]) => {
  const sortedPoints = pointSort(unsortedPoints);
  const polynomial = generateEmptyBNArray(sortedPoints.length);
  for (let i = 0; i < sortedPoints.length; i += 1) {
    const coefficients = interpolationPoly(ecCurve, i, sortedPoints);
    for (let k = 0; k < sortedPoints.length; k += 1) {
      let tmp = new BN(sortedPoints[i].y);
      tmp = tmp.mul(coefficients[k]);
      polynomial[k] = polynomial[k].add(tmp).umod(ecCurve.curve.n);
    }
  }
  return new Polynomial(polynomial, ecCurve);
};

export function lagrangeInterpolatePolynomial(ecCurve: EC, points: Point[]): Polynomial {
  return lagrange(ecCurve, points);
}

export function lagrangeInterpolation(ecCurve: EC, shares: BN[], nodeIndex: BN[]): BN {
  if (shares.length !== nodeIndex.length) {
    throw new Error("shares not equal to nodeIndex length in lagrangeInterpolation");
  }
  let secret = new BN(0);
  for (let i = 0; i < shares.length; i += 1) {
    let upper = new BN(1);
    let lower = new BN(1);
    for (let j = 0; j < shares.length; j += 1) {
      if (i !== j) {
        upper = upper.mul(nodeIndex[j].neg());
        upper = upper.umod(ecCurve.curve.n);
        let temp = nodeIndex[i].sub(nodeIndex[j]);
        temp = temp.umod(ecCurve.curve.n);
        lower = lower.mul(temp).umod(ecCurve.curve.n);
      }
    }
    let delta = upper.mul(lower.invm(ecCurve.curve.n)).umod(ecCurve.curve.n);
    delta = delta.mul(shares[i]).umod(ecCurve.curve.n);
    secret = secret.add(delta);
  }
  return secret.umod(ecCurve.curve.n);
}

// generateRandomPolynomial - determinisiticShares are assumed random
export function generateRandomPolynomial(ecCurve: EC, degree: number, secret?: BN, deterministicShares?: Share[]): Polynomial {
  let actualS = secret;
  if (!secret) {
    actualS = generatePrivateExcludingIndexes([new BN(0)]);
  }
  if (!deterministicShares) {
    const poly = [actualS];
    for (let i = 0; i < degree; i += 1) {
      const share = generatePrivateExcludingIndexes(poly);
      poly.push(share);
    }
    return new Polynomial(poly, ecCurve);
  }
  if (!Array.isArray(deterministicShares)) {
    throw new Error("deterministic shares in generateRandomPolynomial should be an array");
  }

  if (deterministicShares.length > degree) {
    throw new Error("deterministicShares in generateRandomPolynomial should be less or equal than degree to ensure an element of randomness");
  }
  const points: Record<string, Point> = {};
  deterministicShares.forEach((share) => {
    points[share.shareIndex.toString("hex", 64)] = new Point(share.shareIndex, share.share, ecCurve);
  });
  for (let i = 0; i < degree - deterministicShares.length; i += 1) {
    let shareIndex = generatePrivateExcludingIndexes([new BN(0)]);
    while (points[shareIndex.toString("hex", 64)] !== undefined) {
      shareIndex = generatePrivateExcludingIndexes([new BN(0)]);
    }
    points[shareIndex.toString("hex", 64)] = new Point(shareIndex, new BN(generatePrivate()), ecCurve);
  }
  points["0"] = new Point(new BN(0), actualS, ecCurve);
  return lagrangeInterpolatePolynomial(ecCurve, Object.values(points));
}
