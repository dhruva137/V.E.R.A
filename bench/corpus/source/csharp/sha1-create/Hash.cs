using System.Security.Cryptography;

class Hash {
    byte[] Of(byte[] d) => SHA1.Create().ComputeHash(d);
}
