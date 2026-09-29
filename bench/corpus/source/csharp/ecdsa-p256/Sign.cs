using System.Security.Cryptography;

class Sign {
    ECDsa Make() => ECDsa.Create(ECCurve.NamedCurves.nistP256);
}
