using System.Security.Cryptography;

class Keys {
    RSA Make() => RSA.Create(2048);
}
