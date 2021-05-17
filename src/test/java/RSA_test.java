import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.openpgp.PGPKeyPair;
import utility.KeyManagement;
import utility.RSA;

import java.security.KeyPair;

public class RSA_test {
    public static void main(String[] args) {

        try {
            KeyManagement keyManagementUtil = KeyManagement.getInstance();
            PGPKeyPair pair = keyManagementUtil.createPGPKeyPair(RSA.KeySizes.RSA1024);
        } catch (Exception e) {

        }

    }
}
