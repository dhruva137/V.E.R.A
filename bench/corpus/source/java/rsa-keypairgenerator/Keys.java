import java.security.KeyPairGenerator;

public class Keys {
    public static void main(String[] args) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        kpg.generateKeyPair();
    }
}
