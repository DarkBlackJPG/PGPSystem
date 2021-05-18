package utility;

import com.sun.media.jfxmedia.track.Track;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.Console;
import java.io.File;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.*;
import java.util.Scanner;

/**
 * @author Sanja Samardzija 2017/0372
 * TrippleDES object that implements 3DES using specified key.
 * Encrypts and decrypts data passed as byte array for said key.
 *
 */
public class TrippleDES {

    private static final String PROVIDER = "BC";
    private static final String ALGORITHM = "DESede";
    private static final String HASH_ALGORITHM = "SHA-256";
    private static final String TRIPLE_DES_MODE = "DESede/ECB/PKCS7Padding";
    private static final Charset FORMAT = StandardCharsets.UTF_8;
    private static final Integer BYTE_KEY_SIZE = 24;

    private Cipher encrypter ;
    private Cipher decrypter;

    private byte[] key;

    /**
     *  Returns a TrippleDES object that implements 3DES using specified key.
     *
     * <p> A new TrippleDES object implementing the DESede/CBC/PKCS7Padding algorithm with
     * 24 byte key (3 different keys) from the Bouncy Castel provider.
     *
     * @param keyString String key to be used for ciphering
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws NoSuchProviderException
     * @throws InvalidKeyException
     */
    private TrippleDES(String keyString) throws NoSuchPaddingException, NoSuchAlgorithmException,
            NoSuchProviderException, InvalidKeyException {
        Security.addProvider(new BouncyCastleProvider());

        // cipher
        encrypter = Cipher.getInstance(TRIPLE_DES_MODE, PROVIDER);
        decrypter = Cipher.getInstance(TRIPLE_DES_MODE, PROVIDER);

        //3DES key of 24B(192b) => 3 different keys(8B*3)
        key = new byte[BYTE_KEY_SIZE];

        MessageDigest digester = MessageDigest.getInstance(HASH_ALGORITHM, PROVIDER);
        byte[] keyHash = digester.digest(keyString.getBytes(FORMAT));
//        System.out.println(keyP);
        System.arraycopy(keyHash, 0 , key, 0, BYTE_KEY_SIZE);
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
     * For testing of TrippleDES implementation using a console
     * @param args not used
     */
    public static void main(String[] args) {
        try {
            Scanner in = new Scanner(System.in);

            String input, desKey;
            byte[] output, reversed;
            TrippleDES des;
            System.out.println("DES Encryption example");
            System.out.println("----------------------");
            System.out.println("Enter text to encrypt?");
            input = in.nextLine();
            input = input != null ? input : "HELLO";
            System.out.println("Enter a key?");
            desKey = in.nextLine();

            desKey = desKey != null ? desKey : "12345678";
            des = new TrippleDES(desKey);

            output = des.encrypt(input.getBytes(StandardCharsets.UTF_8));
            System.out.println("cipherText (hex):\n" + Hex.toHexString(output));
            reversed = des.decrypt(output);
            System.out.println("Plain text:\n" + new String(reversed, FORMAT));

            System.out.println("Enter absolute path to file for encryption?");
            input = in.nextLine();
            input = input != null ? input : "C:\\Users\\Korisnik\\Desktop\\keys.txt";
            System.out.println("Enter a key?");
            desKey = in.nextLine();

            desKey = desKey != null ? desKey : "12345678";
            des = new TrippleDES(desKey);
            File file =  new File(input);

            output = des.encrypt(Files.readAllBytes(file.toPath()));
            System.out.println("cipherText (hex):\n" + Hex.toHexString(output));
            reversed = des.decrypt(output);
            System.out.println("Plain text:\n" + new String(reversed, FORMAT));

        } catch(Exception e){
            System.out.println("Exception" + e);
        }

    }
}
