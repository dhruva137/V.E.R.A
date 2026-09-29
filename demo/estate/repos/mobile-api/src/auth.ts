import crypto from "crypto";
import jwt from "jsonwebtoken";
import { ml_kem768 } from "@noble/post-quantum/ml-kem";

export function issueSession(userId: string, key: crypto.KeyObject): string {
  return jwt.sign({ sub: userId }, key, { algorithm: "RS256", expiresIn: "15m" });
}

export function deviceFingerprint(input: string): string {
  return crypto.createHash("md5").update(input).digest("hex");
}

export function newDeviceKey() {
  return crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
}

export async function webSigningKey() {
  return crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
}

// PQC pilot for the device-binding handshake.
export function pilotKem() {
  return ml_kem768.keygen();
}
