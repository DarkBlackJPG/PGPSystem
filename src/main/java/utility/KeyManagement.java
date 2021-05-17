package utility;

import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.bcpg.sig.KeyFlags;
import org.bouncycastle.openpgp.PGPKeyPair;

import org.bouncycastle.openpgp.PGPKeyRingGenerator;
import org.bouncycastle.openpgp.PGPSignature;

import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator;

import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

/**
 * Sadrzi operacije koje se ticu kljuceva i obrade za keyring.
 * KeyManagement je singleton!
 * Sve klase u utility paketu bi trebalo da su singleton
 *
 */
public class KeyManagement {
    private String password;
    private String email;
    private String user;
    private String privateKeyRingPath;
    private String publicKeyRingPath;
    private PGPKeyPair keyPair;

    private static KeyManagement keyManagementInstance;

    private KeyManagement() {
        password = null;
        email = null;
        user = null;
        privateKeyRingPath = "../keystore/secret.scr";
        privateKeyRingPath = "../keystore/public.pkr";
        keyPair = null;
    }

    public static KeyManagement getInstance() {
        if(keyManagementInstance == null) {
            keyManagementInstance = new KeyManagement();
        }

        return keyManagementInstance;
    }

    /**
     * Postavi novi password za dohvatanje keyring-a
     * @param password String za password
     */
    public void setPassword(String password) {
        this.password = password;
    }

    /**
     * Dohvatanje vrednosti user-a za kojeg se vezuje keyring - username.
     * @return
     */
    public String getUser() {
        return user;
    }

    /**
     * Postavi username za usera za kojeg vezujemo keyring
     * @param user
     */
    public KeyManagement setUser(String user) {
        this.user = user;
        return this;
    }

    /**
     * Dohvati putanju gde se nalazi privatni keyring
     * @return
     */
    public String getPrivateKeyRingPath() {
        return privateKeyRingPath;
    }


    /**
     * Postavi putanju gde se nalazi privatni keyring
     * @return
     */
    public KeyManagement setPrivateKeyRingPath(String privateKeyRingPath) {
        this.privateKeyRingPath = privateKeyRingPath;
        return this;
    }

    /**
     * Dohvati putanju gde se nalazi javni keyring
     * @return
     */
    public String getPublicKeyRingPath() {
        return publicKeyRingPath;
    }

    /**
     * Postavi putanju gde se nalazi javni keyring
     * @return
     */
    public KeyManagement setPublicKeyRingPath(String publicKeyRingPath) {
        this.publicKeyRingPath = publicKeyRingPath;
        return this;
    }

    public PGPKeyPair getKeyPair() {
        return keyPair;
    }

    public void setKeyPair(PGPKeyPair keyPair) {
        this.keyPair = keyPair;
    }

    public PGPKeyPair createPGPKeyPair(RSA.KeySizes keySize) throws Exception {
        RSA instance = RSA.RSA_GetUtility();
        PGPKeyPair RSA_Pair = instance.RSA_SetKeySize(keySize).RSA_PGPKeyGenerator();
        return RSA_Pair;
    }

    public PGPKeyRingGenerator createPGPKeyRingGenerator() {
        PGPSignatureSubpacketGenerator signHashGen = new PGPSignatureSubpacketGenerator();
        signHashGen.setKeyFlags(false, KeyFlags.SIGN_DATA | KeyFlags.CERTIFY_OTHER);
        signHashGen.setPreferredSymmetricAlgorithms(false, new int[] {
                SymmetricKeyAlgorithmTags.TRIPLE_DES,
                SymmetricKeyAlgorithmTags.IDEA
        });
        signHashGen.setPreferredHashAlgorithms(false, new int[] {
                HashAlgorithmTags.SHA1
        });


        PGPSignatureSubpacketGenerator encHashGen = new PGPSignatureSubpacketGenerator();
        encHashGen.setKeyFlags(false, KeyFlags.ENCRYPT_COMMS | KeyFlags.ENCRYPT_STORAGE);

        return null;
    }
}
