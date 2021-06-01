import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.util.io.Streams;
import pgp.PGP;
import utility.KeyManager.KeyringManager;
import utility.RSA;

import java.io.*;

class PGP_test {

    private static String name = "Test Testicle";
    private static String email = "test@testicle.com";
    private static String pass = "pwd";
    private static String file = "C:\\Users\\Korisnik\\Desktop\\1.txt";
    private static String filePGP = "EncryptionTest.txt.pgp";
    private static String fileASC = "C:\\Users\\Korisnik\\Desktop\\1.txt.asc";
    private static String outputFileName = "123.txt";


    public static void main(String[] args) {
        PGPKeyPair masterKey;
        PGPKeyPair signingKey = null;
        InputStream input;
        String fileName;
        boolean radix64 = true, compress = true;

        try {
/*************************************** KEY GENERATION *****************************************/
//            //////////////////GENERATE KEY PAIR//////////////////////////////
//            KeyringManager keyringManager = new KeyringManager();
//            for (int i = 0; i < 25; i++) {
//                masterKey = RSA.RSA_GetUtility()
//                        .RSA_SetKeySize(RSA.KeySizes.RSA4096)
//                        .RSA_PGPKeyGenerator();
//                signingKey = RSA.RSA_GetUtility()
//                        .RSA_SetKeySize(RSA.KeySizes.RSA4096)
//                        .RSA_PGPKeyGenerator();
//                keyringManager.makeKeyPairs(masterKey, signingKey, name, email, pass);
//                System.out.println(i);
//            }
//            PGPPublicKey publicKey = signingKey.getPublicKey();
//            PGPPrivateKey privateKey = signingKey.getPrivateKey();
//
//            System.out.println("Done making keys");
/*************************************** SIGN AND VERIFY *****************************************/
//            System.out.println();
//            //////////////////////////SIGN//////////////////////////////////////
//            fileName = PGP.signFile(file, privateKey, publicKey, radix64, true);
//            System.out.println("Signed file:");
//            System.out.println("===================================================");
//            input = new FileInputStream(fileName);
//            Streams.pipeAll(input, System.out);
//            input.close();
//            System.out.println();
//            //////////////////////////VERIFY//////////////////////////////////////
//            System.out.println("Verify file:");
//            System.out.println("===================================================");
//            if(PGP.verifyFile(fileASC, KeyringManager.publicKeyFile)){
//                System.out.println("Verified.");
//            } else {
//                System.out.println("Not verified.");
//            }
//            System.out.println("\nradix64 = " + radix64 + " compress = " + compress);



/*************************************** ENCRYPT AND DECRYPT *****************************************/
            System.out.println();
            //////////////////////////ENCRYPTION//////////////////////////////////////
            PGPSecretKeyRingCollection secretKeyRingCollection = new PGPSecretKeyRingCollection(
                    PGPUtil.getDecoderStream(new FileInputStream(KeyringManager.privateKeyFile)),
                    new JcaKeyFingerprintCalculator());
            PGPPublicKey publicKey = secretKeyRingCollection
                                        .getSecretKey(Long.parseUnsignedLong("8478D0C4EA0B91D7",16))
                                        .getPublicKey();
            fileName = PGP.encryptFile(file, new PGPPublicKey[]{publicKey},
            SymmetricKeyAlgorithmTags.TRIPLE_DES, radix64, compress);
            input = new FileInputStream(fileName);
            System.out.println("Encrypted file:");
            System.out.println("===================================================");
            Streams.pipeAll(input, System.out);
            input.close();
            System.out.println();
            //////////////////////////DECRYPTION//////////////////////////////////////
            PGP.decryptFile(fileASC, KeyringManager.privateKeyFile, pass, outputFileName);
            System.out.println("Decrypted file:");
            System.out.println("===================================================");
            input = new FileInputStream(file);
            Streams.pipeAll(input, System.out);
            input.close();
            System.out.println("\nradix64 = " + radix64 + " compress = " + compress);



/*************************************** SIGN+VERIFY AND ENCRYPT+DECRYPT *****************************************/
//            //////////////////////////SIGN AND ENCRYPT//////////////////////////////////////
//            fileName = PGP.signAndEncrypt(file, privateKey, publicKey, new PGPPublicKey[]{publicKey},
//                    SymmetricKeyAlgorithmTags.TRIPLE_DES, radix64, compress);
//            System.out.println("Signed and encrypted file:");
//            System.out.println("===================================================");
//            input = new FileInputStream(fileName);
//            Streams.pipeAll(input, System.out);
//            input.close();
//            System.out.println();
//            //////////////////////////DECRYPTION AND VERIFICATION//////////////////////////////////////
//            PGP.decryptAndVerify(fileName, KeyringManager.privateKeyFile,
//                    KeyringManager.publicKeyFile, pass);
//            System.out.println("Decrypted file:");
//            System.out.println("===================================================");
//            input = new FileInputStream(file);
//            Streams.pipeAll(input, System.out);
//            input.close();
//            System.out.println("\nradix64 = " + radix64 + " compress = " + compress);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}