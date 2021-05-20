import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.openpgp.*;
import utility.KeyManagement;
import utility.RSA;
import utility.User;

import java.security.KeyPair;
import java.util.ArrayList;

public class RSA_test {
    public static void main(String[] args) {
        String name = "ss";
        String email = "stefant@gmail.com";
        String pass = "123";
        User.loginUser(name, email, pass);

        try {
            KeyManagement keyManagement = new KeyManagement();
            keyManagement.generateKeyring(RSA.KeySizes.RSA1024);
            PGPSecretKeyRing s = keyManagement.get();
            ArrayList<PGPSecretKeyRing> ss = new ArrayList<>();
            ss.add(s);
            PGPSecretKeyRingCollection sss = new PGPSecretKeyRingCollection(ss);
            System.out.println();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
