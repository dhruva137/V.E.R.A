import jwt from 'jsonwebtoken';

export function token(payload: object, secret: string): string {
  return jwt.sign(payload, secret, { algorithm: 'HS256' });
}
