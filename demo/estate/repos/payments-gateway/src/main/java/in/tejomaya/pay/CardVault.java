package in.tejomaya.pay;

import java.security.*;
import java.security.spec.RSAKeyGenParameterSpec;
import javax.crypto.Cipher;
import javax.net.ssl.SSLContext;

public class CardVault {
    // Legacy card-data envelope, kept for the 2014 settlement format.
    public byte[] seal(byte[] pan, Key key) throws Exception {
        Cipher cipher = Cipher.getInstance("DESede/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(pan);
    }

    public KeyPair signingKey() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(new RSAKeyGenParameterSpec(3072, RSAKeyGenParameterSpec.F4));
        return kpg.generateKeyPair();
    }

    public byte[] signReceipt(PrivateKey key, byte[] receipt) throws Exception {
        Signature signature = Signature.getInstance("SHA1withRSA");
        signature.initSign(key);
        signature.update(receipt);
        return signature.sign();
    }

    public SSLContext legacyAcquirerLink() throws Exception {
        return SSLContext.getInstance("TLSv1");
    }

    public Cipher configured(String transformation) throws Exception {
        return Cipher.getInstance(transformation);
    }
}
