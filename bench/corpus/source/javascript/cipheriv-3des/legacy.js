const crypto = require('crypto');

function enc(key, iv, data) {
  const c = crypto.createCipheriv('des-ede3-cbc', key, iv);
  return Buffer.concat([c.update(data), c.final()]);
}
