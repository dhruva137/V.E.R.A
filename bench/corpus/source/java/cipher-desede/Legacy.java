import javax.crypto.Cipher;

public class Legacy {
    Cipher cipher() throws Exception {
        return Cipher.getInstance("DESede/CBC/PKCS5Padding");
    }
}
