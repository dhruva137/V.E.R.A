import logging

log = logging.getLogger(__name__)

# TODO: stop using RSA and MD5 once the partner migrates.
log.info("rotating RSA keys; md5 checks disabled")
