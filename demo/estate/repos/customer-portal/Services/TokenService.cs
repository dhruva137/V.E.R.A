using System.Security.Authentication;
using System.Security.Cryptography;

namespace Tejomaya.Portal.Services;

public class TokenService
{
    private readonly RSA _signer = RSA.Create(2048);
    public byte[] LegacyHash(byte[] data) => SHA1.HashData(data);
    public SslProtocols PartnerProtocols => SslProtocols.Tls11;
    public MLKem PilotKem() => MLKem.GenerateKey(MLKemAlgorithm.MLKem768);
}
