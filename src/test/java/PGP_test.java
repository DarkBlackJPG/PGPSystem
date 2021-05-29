import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.util.io.Streams;
import pgp.PGP;
import utility.KeyManager.KeyringManager;
import utility.RSA;

import java.io.*;

class PGP_test {

    private static String name = "Test Testicle";
    private static String email = "test@testicle.com";
    private static String pass = "pwd";
    private static String file = "EncryptionTest.txt";
    private static String fileBPG = "EncryptionTest.txt.bpg";
    private static String fileASC = "EncryptionTest.txt.asc";
    private static String outputFileName = "123.txt";


    public static void main(String[] args) {
        PGPKeyPair masterKey;
        InputStream input;
        String fileName;

        try {
            //////////////////GENERATE KEY PAIR//////////////////////////////
            masterKey = RSA.RSA_GetUtility()
                    .RSA_SetKeySize(RSA.KeySizes.RSA4096)
                    .RSA_PGPKeyGenerator();
            PGPKeyPair signingKey = RSA.RSA_GetUtility()
                    .RSA_SetKeySize(RSA.KeySizes.RSA4096)
                    .RSA_PGPKeyGenerator();
            KeyringManager keyringManager = new KeyringManager();
            keyringManager.makeKeyPairs(masterKey, signingKey, name, email, pass);
            PGPPublicKey publicKey = signingKey.getPublicKey();
            PGPPrivateKey privateKey = signingKey.getPrivateKey();

//            System.out.println();
//            //////////////////////////SIGN//////////////////////////////////////
//            fileName = PGP.signFile(file, privateKey, publicKey, true, true);
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
//                System.out.println("Verified radix64: " + radix64 + " compress: " + compress);
//            } else {
//                System.out.println("Not verified radix64: " + radix64 + " compress: " + compress);
//            }

//            System.out.println();
//            //////////////////////////ENCRYPTION//////////////////////////////////////
//            fileName = PGP.encryptFile(file, new PGPPublicKey[]{publicKey},
//                    SymmetricKeyAlgorithmTags.TRIPLE_DES, true, false);
//            input = new FileInputStream(fileName);
//            System.out.println("Encrypted file:");
//            System.out.println("===================================================");
//            Streams.pipeAll(input, System.out);
//            input.close();
//
//            System.out.println();
//            //////////////////////////DECRYPTION//////////////////////////////////////
//            PGP.decryptFile(fileASC, KeyringManager.privateKeyFile, pass, outputFileName);
//            System.out.println("Decrypted file:");
//            System.out.println("===================================================");
//            input = new FileInputStream(file);
//            Streams.pipeAll(input, System.out);
//            input.close();

            //////////////////////////SIGN AND ENCRYPT//////////////////////////////////////
            fileName = PGP.signAndEncrypt(file, privateKey, publicKey, new PGPPublicKey[]{publicKey},
                    SymmetricKeyAlgorithmTags.TRIPLE_DES, true, true);
            System.out.println("Signed and encrypted file:");
            System.out.println("===================================================");
            input = new FileInputStream(fileName);
            Streams.pipeAll(input, System.out);
            input.close();
            System.out.println();
            //////////////////////////DECRYPTION AND VERIFICATION//////////////////////////////////////
            PGP.decryptAndVerify(fileASC, KeyringManager.privateKeyFile,
                    KeyringManager.publicKeyFile, pass);
            System.out.println("Decrypted file:");
            System.out.println("===================================================");
            input = new FileInputStream(file);
            Streams.pipeAll(input, System.out);
            input.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}