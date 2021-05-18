import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.openpgp.*;
import utility.KeyManagement;
import utility.RSA;
import utility.User;

import java.security.KeyPair;

public class RSA_test {
    public static void main(String[] args) {
        String name = "Stefan Teslic";
        String email = "stefant@gmail.com";
        String pass = "123";

        User.loginUser(name, email, pass);


        try {
            KeyManagement keyManagement = new KeyManagement();
            keyManagement.generateKeyring(RSA.KeySizes.RSA2048);
            keyManagement.saveKeyrings();
            PGPSecretKey s = keyManagement.getAsymmetricSigningKey();
            System.out.println();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
