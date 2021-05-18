package utility;
import java.math.BigInteger;
import java.security.*;
import java.util.Date;

import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
//import org.bouncycastle.bcpg.sig.Features;
import org.bouncycastle.bcpg.sig.KeyFlags;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.KeyFingerPrintCalculator;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPDigestCalculatorProviderBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyPair;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyEncryptorBuilder;

/**
 * RSA Class je singleton klasa.
 *  Koristimo za generisanje parova, sifrovanje i desifrovanje.
 */
public class RSA {
    private KeyPairGenerator keyPairGenerator;
    private String publicExponent;

    private static RSA Utility_RSA;
    private KeySizes keySize;

    /**
     * Sluzi nam da ogranicimo sta korisnik moze da unese
     */
    public static enum KeySizes {
        RSA1024 (1024),
        RSA2048 (2048),
        RSA4096 (4096);


        private final int keySize;

        KeySizes (int keySize) {
            this.keySize = keySize;
        }

        public int getKeySize() {
            return this.keySize;
        }
    }

    private RSA() throws NoSuchProviderException, NoSuchAlgorithmException {
        keySize = KeySizes.RSA1024;
        publicExponent = "10001";
        Security.addProvider(new BouncyCastleProvider());
        keyPairGenerator = KeyPairGenerator.getInstance("RSA", "BC");
    }

    /**
     * Dohvata instancu RSA
     * @return RSA
     */
    public static RSA RSA_GetUtility() throws NoSuchProviderException, NoSuchAlgorithmException {
        if (RSA.Utility_RSA == null) {
            RSA.Utility_RSA = new RSA();
        }
        return RSA.Utility_RSA;
    }

    /**
     * Postavlja novi keysize.
     * Default je 1024
     * @param keySize Velicina kljuca, uzima se enum KeySizes koji je static
     * @return RSA - graditelj pattern
     */
    public RSA RSA_SetKeySize(KeySizes keySize) {
        keySize = keySize;
        return this;
    }

    /**
     * Ovo je zapravo ono e sto stavljamo
     * Default je "10001"
     * @param exponent U string formatu, konvertuje se u hex
     * @return Builder pattern, vraca singleton
     */
    public RSA RSA_SetPublicExponent(String exponent) {
        publicExponent = exponent;
        return this;
    }

    /**
     * Generisanje parova kljuceva.
     * Za promenu velicine kljuca, prethodno je neophodno da se
     * @return
     * @throws NoSuchAlgorithmException
     */
    public KeyPair RSA_KeyGenerator() throws NoSuchAlgorithmException {
        keyPairGenerator.initialize(keySize.getKeySize());
        return keyPairGenerator.generateKeyPair();
    }

    /**
     * Ova metoda genrise par kljuceva uz pomoc RSA.
     * Generise se PGPKeyPair koji u sebi sadrzi dosta nekih info kao na primer,
     * koji alg je koriscen za generisanje, javni i privatni, key id itd..
     *
     * @return PGPKeyPair
     * @throws Exception
     */
    public PGPKeyPair RSA_PGPKeyGenerator() throws Exception {
        keyPairGenerator.initialize(keySize.getKeySize());
        KeyPair pair = keyPairGenerator.generateKeyPair();
        JcaPGPKeyPair jcaPGPKeyPair = new JcaPGPKeyPair(1, pair, new Date());
        return new PGPKeyPair(jcaPGPKeyPair.getPublicKey(), jcaPGPKeyPair.getPrivateKey());
    }

}
