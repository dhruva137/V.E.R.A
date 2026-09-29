const crypto = require('crypto');

function etag(body) {
  return crypto.createHash('md5').update(body).digest('hex');
}
