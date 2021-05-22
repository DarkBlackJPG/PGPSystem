import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyPair;
import utility.ExportedKeyData;
import utility.KeyManager.KeyringManager;
import utility.RSA;

import java.io.*;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.ArrayList;

/*
    Prolazi testove
 */
public class RSA_test {
    /**
     * TODO: Mora obrada izuzetka ako uvozim javni kljuc, a trazio sam tajni kljuc, ili mozda bolje da se
     * napravi analiza sta treba da se uveze --- Kako?
     */
    private static String name = "Test Testicle";
    private static String email = "test@testicle.com";
    private static String pass = "pwd";
    private static String importPublicPath = "C:\\Users\\stefa\\OneDrive\\Desktop\\PGP FINAL\\src\\test\\resources\\KleoImportPub.asc";
    private static String exportPublicPath = "C:\\Users\\stefa\\OneDrive\\Desktop\\PGP FINAL\\src\\test\\resources\\PublicExp.asc";
    private static String exportSecretPath = "C:\\Users\\stefa\\OneDrive\\Desktop\\PGP FINAL\\src\\test\\resources\\SecretExp.asc";
    private static String importSecretPath = "C:\\Users\\stefa\\OneDrive\\Desktop\\PGP FINAL\\src\\test\\resources\\KleoImportSec.asc";

    private static void TEST_exportPublic() {
        File file = new File(exportPublicPath);
        // Uvek pravi novi fajl
        try {
            file.createNewFile();
            FileOutputStream fileOutputStream = new FileOutputStream(file);
            PGPKeyPair keyPair = RSA.RSA_GetUtility()
                    .RSA_SetKeySize(RSA.KeySizes.RSA4096)
                    .RSA_PGPKeyGenerator();
            KeyringManager keyringManager = new KeyringManager();
            keyringManager.makeKeyPairs(keyPair, name, email, pass);

            ArrayList<ExportedKeyData> exportedKeyData = keyringManager.generatePublicKeyList();
            keyringManager.exportPublicKey(exportedKeyData.get(0).getKeyID(), fileOutputStream);

            System.out.println("Proveri output i uvezi u kleo");
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (PGPException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static void TEST_exportSecret() {
        File file = new File(exportSecretPath);
        // Uvek pravi novi fajl
        try {
            file.createNewFile();
            FileOutputStream fileOutputStream = new FileOutputStream(file);
            PGPKeyPair keyPair = RSA.RSA_GetUtility()
                    .RSA_SetKeySize(RSA.KeySizes.RSA4096)
                    .RSA_PGPKeyGenerator();
            KeyringManager keyringManager = new KeyringManager();
            keyringManager.makeKeyPairs(keyPair, name, email, pass);

            ArrayList<ExportedKeyData> exportedKeyData = keyringManager.generatePublicKeyList();
            keyringManager.exportSecretKey(exportedKeyData.get(0).getKeyID(), fileOutputStream);

            System.out.println("Proveri output i uvezi u kleo");
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (PGPException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static void TEST_importPublic() {
        File file = new File(importPublicPath);
        try {
            FileInputStream fis = new FileInputStream(file);
            KeyringManager keyringManager = new KeyringManager();
            keyringManager.importPublicKeyring(fis);

            ArrayList<ExportedKeyData> exportedKeyData = keyringManager.generatePublicKeyList();

            for (ExportedKeyData element :
                    exportedKeyData) {
                System.out.println(element);
            }

        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (PGPException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private static void TEST_importSecret() {
        File file = new File(importSecretPath);
        try {
            FileInputStream fis = new FileInputStream(file);
            KeyringManager keyringManager = new KeyringManager();
            keyringManager.importSecretKeyring(fis);

            ArrayList<ExportedKeyData> exportedKeyData = keyringManager.generatePublicKeyList();

            for (ExportedKeyData element :
                    exportedKeyData) {
                System.out.println(element);
            }

        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (PGPException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private static void TEST_deletePublic() {
        File file = new File(exportSecretPath);
        // Uvek pravi novi fajl
        try {
            file.createNewFile();
            FileOutputStream fileOutputStream = new FileOutputStream(file);
            PGPKeyPair keyPair = RSA.RSA_GetUtility()
                    .RSA_SetKeySize(RSA.KeySizes.RSA4096)
                    .RSA_PGPKeyGenerator();
            KeyringManager keyringManager = new KeyringManager();
            keyringManager.makeKeyPairs(keyPair, name, email, pass);

            ArrayList<ExportedKeyData> exportedKeyData = keyringManager.generatePublicKeyList();
            for (ExportedKeyData element :
                    exportedKeyData) {
                System.out.println(element);
            }
            System.out.println("=== Brisemo ===");
            keyringManager.removePublicKey(exportedKeyData.get(0).getKeyID());
            exportedKeyData = keyringManager.generatePublicKeyList();
            for (ExportedKeyData element :
                    exportedKeyData) {
                System.out.println(element);
            }

            System.out.println("Proveri output i uvezi u kleo");
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (PGPException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static void TEST_deleteSecret_correctPWD() {
        File file = new File(exportSecretPath);
        // Uvek pravi novi fajl
        try {
            file.createNewFile();
            FileOutputStream fileOutputStream = new FileOutputStream(file);
            PGPKeyPair keyPair = RSA.RSA_GetUtility()
                    .RSA_SetKeySize(RSA.KeySizes.RSA4096)
                    .RSA_PGPKeyGenerator();
            KeyringManager keyringManager = new KeyringManager();
            keyringManager.makeKeyPairs(keyPair, name, email, pass);

            ArrayList<ExportedKeyData> exportedKeyData = keyringManager.generatePublicKeyList();
            for (ExportedKeyData element :
                    exportedKeyData) {
                System.out.println(element);
            }
            System.out.println("=== Brisemo ===");
            keyringManager.removeSecretKey(exportedKeyData.get(0).getKeyID(), pass);
            exportedKeyData = keyringManager.generatePublicKeyList();
            for (ExportedKeyData element :
                    exportedKeyData) {
                System.out.println(element);
            }

            System.out.println("Proveri output i uvezi u kleo");
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (PGPException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static void TEST_deleteSecret_incorrectPWD() {
        File file = new File(exportSecretPath);
        // Uvek pravi novi fajl
        try {
            file.createNewFile();
            FileOutputStream fileOutputStream = new FileOutputStream(file);
            PGPKeyPair keyPair = RSA.RSA_GetUtility()
                    .RSA_SetKeySize(RSA.KeySizes.RSA4096)
                    .RSA_PGPKeyGenerator();
            KeyringManager keyringManager = new KeyringManager();
            keyringManager.makeKeyPairs(keyPair, name, email, pass);

            ArrayList<ExportedKeyData> exportedKeyData = keyringManager.generatePublicKeyList();
            for (ExportedKeyData element :
                    exportedKeyData) {
                System.out.println(element);
            }
            System.out.println("=== Brisemo ===");
            keyringManager.removeSecretKey(exportedKeyData.get(0).getKeyID(), "321");
            exportedKeyData = keyringManager.generatePublicKeyList();
            for (ExportedKeyData element :
                    exportedKeyData) {
                System.out.println(element);
            }

            System.out.println("Proveri output i uvezi u kleo");
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (PGPException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @Deprecated
    private static void TEST_importPublicKey() {
        try {

            KeyringManager keyringManager = new KeyringManager();
            File f = new File("C:\\Users\\stefa\\OneDrive\\Desktop\\KleoImportPub.asc");

            FileInputStream fis = new FileInputStream(f);
            keyringManager.importPublicKeyring(fis);

            ArrayList<ExportedKeyData> keyData = keyringManager.generatePublicKeyList();

            for (ExportedKeyData element :
                    keyData) {
                System.out.println(element.toString());
            }
//            File filename = new File("test.asc");
//            filename.createNewFile();
//            FileOutputStream fos = new FileOutputStream(filename);
//            keyringManager.exportKeyPair(keyData.get(0).getKeyID(), fos);
//            System.out.println("=========================");


        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @Deprecated
    private static void exportImportSecretKey() throws Exception {
        PGPKeyPair keyPair = RSA.RSA_GetUtility()
                .RSA_SetKeySize(RSA.KeySizes.RSA1024)
                .RSA_PGPKeyGenerator();

        KeyringManager keyringManager = new KeyringManager();
        keyringManager.makeKeyPairs(keyPair, name, email, pass);

        File f = new File("C:\\Users\\stefa\\OneDrive\\Desktop\\test_secret.asc");
        f.createNewFile();
        FileOutputStream fos = new FileOutputStream(f);
        ArrayList<ExportedKeyData> keyData = keyringManager.generatePublicKeyList();

        long KeyId = keyData.get(0).getKeyID();
        keyringManager.exportSecretKey(KeyId, fos);
        fos.close();

        FileInputStream fis = new FileInputStream(f);
        keyringManager = new KeyringManager();
        keyringManager.importSecretKeyring(fis);
        keyData = keyringManager.generatePublicKeyList();
        for (ExportedKeyData element :
                keyData) {
            System.out.println(keyData);
        }


    }

    private static void begin_test() {
        System.out.println("TEST_exportPublic");
        TEST_exportPublic();
        System.out.println("TEST_exportSecret");
        TEST_exportSecret();
        System.out.println("TEST_importPublic");
        TEST_importPublic();
        System.out.println("TEST_importSecret");
        TEST_importSecret();
        System.out.println("TEST_deletePublic");
        TEST_deletePublic();
        System.out.println("TEST_deleteSecret_correctPWD");
        TEST_deleteSecret_correctPWD();
        System.out.println("TEST_deleteSecret_incorrectPWD");
        TEST_deleteSecret_incorrectPWD();
    }

    public static void main(String[] args) {
        begin_test();
    }
}
