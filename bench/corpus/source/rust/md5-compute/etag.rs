fn etag(data: &[u8]) -> String {
    format!("{:x}", md5::compute(data))
}
