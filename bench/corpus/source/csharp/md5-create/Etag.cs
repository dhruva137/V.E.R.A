using System.Security.Cryptography;

class Etag {
    byte[] Of(byte[] d) => MD5.Create().ComputeHash(d);
}
