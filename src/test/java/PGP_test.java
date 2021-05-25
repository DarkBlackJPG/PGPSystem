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
    private static String fileToEncrypt = "EncryptionTest.txt";
    private static String fileToDecrypt = "EncryptionTest.txt.asc";
    private static String outputFileName = "123.txt";
    private static String fileToSign = "EncryptionTest.txt";


    public static void main(String[] args) {
        PGPKeyPair masterKey;
        InputStream input;

        try {
            PGP pgp = PGP.getInstancePGP();
            masterKey = RSA.RSA_GetUtility()
                    .RSA_SetKeySize(RSA.KeySizes.RSA4096)
                    .RSA_PGPKeyGenerator();
            PGPKeyPair signingKey = RSA.RSA_GetUtility()
                    .RSA_SetKeySize(RSA.KeySizes.RSA4096)
                    .RSA_PGPKeyGenerator();
            KeyringManager keyringManager = new KeyringManager();
            keyringManager.makeKeyPairs(masterKey, signingKey, name, email, pass);
            PGPPublicKey publicKey = signingKey.getPublicKey();
            System.out.println(publicKey.getKeyID());
            PGPPrivateKey privateKey = signingKey.getPrivateKey();
            System.out.println(privateKey.getKeyID());
//
//            ///////////////////////////////////////////
//            pgp.encryptFile(fileToDecrypt,fileToEncrypt,new PGPPublicKey[]{publicKey},
//                    SymmetricKeyAlgorithmTags.TRIPLE_DES, false, true);
//            input = new FileInputStream(fileToDecrypt);
//            System.out.println("Encrypted file:");
//            System.out.println("===================================================");
//            Streams.pipeAll(input, System.out);
//            input.close();
//
//            /////////////////////////////////////////////////
//            pgp.decryptFile(fileToDecrypt, KeyringManager.privateKeyFile, pass, outputFileName);
//            System.out.println("Decrypted file:");
//            System.out.println("===================================================");
//            try {
//                input = new FileInputStream(fileToEncrypt);
//            } catch (Exception e){
//                input = new FileInputStream(fileToDecrypt);
//            }
//            Streams.pipeAll(input, System.out);
//            input.close();
//
//            System.out.println();
//            /////////////////////////////////////////////////
            String signed = pgp.signFile(fileToSign, privateKey, publicKey, true, true);
            System.out.println("Signed file:");
            System.out.println("===================================================");
            input = new FileInputStream(signed);
            Streams.pipeAll(input, System.out);
            input.close();

            System.out.println("Verify file:");
            System.out.println("===================================================");
//            if(pgp.verifyFile(signed, KeyringManager.publicKeyFile)){
            if(pgp.verifyFile(fileToDecrypt, KeyringManager.publicKeyFile)){
                System.out.println("Verified");
            } else {
                System.out.println("Not verified");
            }
        } catch (Exception e) {
            e.printStackTrace();
            System.out.println(e);
        }



    }
}