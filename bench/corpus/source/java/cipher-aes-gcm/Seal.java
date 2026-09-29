import javax.crypto.Cipher;

public class Seal {
    Cipher cipher() throws Exception {
        return Cipher.getInstance("AES/GCM/NoPadding");
    }
}
