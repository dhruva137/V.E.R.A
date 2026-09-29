import javax.crypto.Mac;

public class Hmac {
    Mac mac() throws Exception {
        return Mac.getInstance("HmacSHA256");
    }
}
