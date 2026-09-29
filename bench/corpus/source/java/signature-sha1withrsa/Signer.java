import java.security.Signature;

public class Signer {
    Signature signer() throws Exception {
        return Signature.getInstance("SHA1withRSA");
    }
}
