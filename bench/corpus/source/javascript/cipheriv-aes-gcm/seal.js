const crypto = require('crypto');

function seal(key, iv) {
  return crypto.createCipheriv('aes-256-gcm', key, iv);
}
