import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.openpgp.*;
import utility.KeyManagement;
import utility.RSA;
import utility.User;

import java.security.KeyPair;

public class RSA_test {
    public static void main(String[] args) {
        String name = "ss";
        String email = "stefant@gmail.com";
        String pass = "123";
        User.loginUser(name, email, pass);

        try {
            KeyManagement keyManagement = new KeyManagement();
            keyManagement.generateKeyring(RSA.KeySizes.RSA1024);
            keyManagement.saveKeyrings();
            PGPSecretKey s = keyManagement.getAsymmetricSigningKey();
            KeyManagement.exportSecretKey(s, "C:\\Users\\stefa\\OneDrive\\Desktop\\out.asc");
            System.out.println();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
