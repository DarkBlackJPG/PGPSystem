package utility;

import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.bcpg.sig.KeyFlags;
import org.bouncycastle.jcajce.provider.digest.SHA1;
import org.bouncycastle.openpgp.*;

import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyEncryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Collections;

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
    private PGPKeyRingGenerator keyRingGenerator;

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
    public KeyManagement setPassword(String password) {
        this.password = password;
        return this;
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

    /**
     * Pravimo RSA keypair
     * @param keySize
     * @return
     * @throws Exception
     */
    public PGPKeyPair createPGPKeyPair(RSA.KeySizes keySize) throws Exception {
        RSA instance = RSA.RSA_GetUtility();
        keyPair = instance.RSA_SetKeySize(keySize).RSA_PGPKeyGenerator();
        return keyPair;
    }

    public PGPKeyRingGenerator getKeyRingGenerator() {
        return keyRingGenerator;
    }


    /**
     * Ne znam sta ovo tacno radi i kako radi, ali
     * poenta je da ti imas keyring generator koji
     * moze da generise nove kljuceve iz master kljuca
     * Adrian nije dobro rekao na proslogodisnjim konsul
     * @return
     * @throws PGPException
     */
    public PGPKeyRingGenerator createPGPKeyRingGenerator() throws PGPException {
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

        keyRingGenerator =  new PGPKeyRingGenerator(
            PGPSignature.DEFAULT_CERTIFICATION,
            keyPair,
            user,
            new BcPGPDigestCalculatorProvider().get(HashAlgorithmTags.SHA1),
            signHashGen.generate(),
            encHashGen.generate(),
            new BcPGPContentSignerBuilder(PGPPublicKey.RSA_SIGN, HashAlgorithmTags.SHA1),
            new BcPBESecretKeyEncryptorBuilder(PGPEncryptedData.IDEA).build(password.toCharArray())
        );

        return keyRingGenerator;
    }

    // TODO Implementirati cuvanje keyring-a
    public void saveKeyrings() throws IOException, PGPException {


    }
}
