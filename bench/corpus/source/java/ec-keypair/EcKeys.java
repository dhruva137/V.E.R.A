import java.security.KeyPairGenerator;
import java.security.spec.ECGenParameterSpec;

public class EcKeys {
    void make() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(new ECGenParameterSpec("secp256r1"));
    }
}
