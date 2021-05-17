import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.PGPKeyRingGenerator;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import utility.KeyManagement;
import utility.RSA;

import java.security.KeyPair;

public class RSA_test {
    public static void main(String[] args) {

        try {
            KeyManagement keyManagementUtil = KeyManagement.getInstance();
            keyManagementUtil.createPGPKeyPair(RSA.KeySizes.RSA1024);
            keyManagementUtil.setUser("Stefan Teslic").setPassword("pwd");
            keyManagementUtil.createPGPKeyRingGenerator();
            keyManagementUtil.saveKeyrings();

        } catch (Exception e) {
            System.out.println("asdas");
            System.out.println(e.getMessage());
        }

    }
}
