import org.apache.tools.ant.DirectoryScanner;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.openpgp.*;
import utility.ExportedKeyData;
import utility.KeyManagement;
import utility.KeyManager.KeyringManager;
import utility.RSA;
import utility.User;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.KeyPair;
import java.util.ArrayList;
import java.util.Scanner;

public class RSA_test {
    private static String name = "ss";
    private static String email = "stefant@gmail.com";
    private static String pass = "123";


    private static void TEST_importPublicKey() {
        try {

            KeyringManager keyringManager = new KeyringManager();
            File f = new File("C:\\Users\\stefa\\OneDrive\\Desktop\\Stefan Teslić_0xC211E448_public.asc");

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

    public static void main(String[] args) {
        TEST_importPublicKey();


//        try {
//            PGPKeyPair keyPair = RSA.RSA_GetUtility()
//                    .RSA_SetKeySize(RSA.KeySizes.RSA4096)
//                    .RSA_PGPKeyGenerator();
//
//            KeyringManager keyringManager = new KeyringManager();
//            keyringManager.makeKeyPairs(keyPair, name, email, pass);
//
//            ArrayList<ExportedKeyData> keyData = keyringManager.generatePublicKeyList();
//            File f = new File("output.asc");
//            f.createNewFile();
//            FileOutputStream fos = new FileOutputStream(f);
//            keyringManager.exportPublicKey(keyData.get(0).getKeyID(), fos);
//        } catch (Exception e) {
//            e.printStackTrace();
//        }
    }
}
