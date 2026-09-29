import java.security.MessageDigest;

public class Checksum {
    public static byte[] of(byte[] data) throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5");
        return md.digest(data);
    }
}
