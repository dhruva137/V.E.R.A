import { createHash } from 'crypto';

export const sha = (s: string) => createHash('sha1').update(s).digest('hex');
