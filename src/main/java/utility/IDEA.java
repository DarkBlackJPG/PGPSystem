package utility;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.*;
import java.util.Scanner;

/**
 * @author Sanja Samardzija 2017/0372
 * {@code IDEA} object that implements 3DES using specified key.
 * Encrypts and decrypts data passed as byte array for said key.
 *
 */
public class IDEA {

    private static final String PROVIDER = "BC";
    private static final String ALGORITHM = "IDEA";
    private static final String HASH_ALGORITHM = "SHA-1";
    private static final String IDEA_MODE = "IDEA/ECB/ISO7816-4Padding";
    private static final Charset FORMAT = StandardCharsets.UTF_8;
    private static final Integer BYTE_KEY_SIZE = 16;

    private Cipher encrypter ;
    private Cipher decrypter;

    private byte[] key;

    /**
     *  Returns a {@code IDEA} object that implements 3DES using specified key.
     *
     * <p> A new {@code IDEA} object implementing the DESede/CBC/PKCS7Padding algorithm with
     * 24 byte key (3 different keys) from the Bouncy Castel provider.
     *
     * @param keyString String key to be used for ciphering
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws NoSuchProviderException
     * @throws InvalidKeyException
     */
    private IDEA(String keyString) throws NoSuchPaddingException, NoSuchAlgorithmException,
            NoSuchProviderException, InvalidKeyException {
        Security.addProvider(new BouncyCastleProvider());

        // cipher
        encrypter = Cipher.getInstance(IDEA_MODE, PROVIDER);
        decrypter = Cipher.getInstance(IDEA_MODE, PROVIDER);

        //IDEA key of 16B(128b)
        key = new byte[BYTE_KEY_SIZE];

        MessageDigest digester = MessageDigest.getInstance(HASH_ALGORITHM, PROVIDER);
//        byte[] keyHash = digester.digest(keyString.getBytes(FORMAT));
//        System.out.println(keyHash);
//        System.arraycopy(keyHash, 0 , key, 0, BYTE_KEY_SIZE);
        System.arraycopy(digester.digest(keyString.getBytes(FORMAT)), 0 , key, 0, BYTE_KEY_SIZE);
        SecretKeySpec secretKeySpec =  new SecretKeySpec(key, 0, BYTE_KEY_SIZE, ALGORITHM);
        encrypter.init(Cipher.ENCRYPT_MODE, secretKeySpec);
        decrypter.init(Cipher.DECRYPT_MODE, secretKeySpec);
    }

    /**
     *
     * @param message Byte array to be encrypted
     * @return Encrypted message as byte array
     * @throws ShortBufferException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     *
     */
    public byte[] encrypt(byte [] message) throws ShortBufferException, IllegalBlockSizeException, BadPaddingException {
        byte[] encrypted = new byte[encrypter.getOutputSize(message.length)];
        encrypter.doFinal(message, 0, message.length, encrypted, 0);
        return encrypted;
    }

    /**
     *
     * @param message Byte array to be decrypted
     * @return Decrypted message as byte array
     * @throws ShortBufferException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     */
    public byte[] decrypt(byte [] message) throws ShortBufferException, IllegalBlockSizeException, BadPaddingException {
        byte[] decrypted = new byte[decrypter.getOutputSize(message.length)];
        decrypter.doFinal(message, 0, message.length, decrypted, 0);
//        System.out.println(new String(decrypted, FORMAT));
        return decrypted;
    }

    /**
     * For testing of {@code IDEA} class using a console
     * @param args not used
     */
    public static void main(String[] args) {
        try {
            Scanner in = new Scanner(System.in);

            String input, ideaKey;
            byte[] output, reversed;
            utility.IDEA idea;
            System.out.println("IDEA Encryption example");
            System.out.println("----------------------");
            System.out.println("Enter text to encrypt?");
            input = in.nextLine();
            input = input.equals("") ? input : "HELLO";
            System.out.println("Enter a key?");
            ideaKey = in.nextLine();

            ideaKey = ideaKey.equals("") ? ideaKey : "12345678";
            idea = new utility.IDEA(ideaKey);

            output = idea.encrypt(input.getBytes(FORMAT));
            System.out.println("cipherText (hex):\n" + Hex.toHexString(output));
            reversed = idea.decrypt(output);
            System.out.println("Plain text:\n" + new String(reversed, FORMAT));

            System.out.println("Enter absolute path to file for encryption?");
            input = in.nextLine();
            input = input.equals("") ? input : "C:\\Users\\Korisnik\\Desktop\\keys.txt";
            File file =  new File(input);
            if(!file.exists() || !file.canRead() || !file.isFile()){
                System.out.println("INVALID FILE! Enter absolute path to file for encryption?");
                input = in.nextLine();
                input = input.equals("") ? input : "C:\\Users\\Korisnik\\Desktop\\New Text Document.txt";
                file =  new File(input);
            }
            output = idea.encrypt(Files.readAllBytes(file.toPath()));
            System.out.println("Enter a key?");
            ideaKey = in.nextLine();
            ideaKey = ideaKey.equals("") ? ideaKey : "12345678";

            idea = new utility.IDEA(ideaKey);
            System.out.println("cipherText (hex):\n" + Hex.toHexString(output));
            reversed = idea.decrypt(output);
            System.out.println("Plain text:\n" + new String(reversed, FORMAT));
        } catch(Exception e){
            System.out.println("Exception" + e);
        }

    }
}
