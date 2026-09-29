import javax.net.ssl.SSLContext;

public class Client {
    SSLContext context() throws Exception {
        return SSLContext.getInstance("TLSv1");
    }
}
