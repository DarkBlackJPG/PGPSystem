package etf.openpgp.ts170124dss170372d.utility;

import org.bouncycastle.bcpg.CompressionAlgorithmTags;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;

import java.io.*;
import java.security.NoSuchProviderException;
import java.util.Iterator;

public class PGPutil {

    private static final String PROVIDER = "BC";
    private static final int COMPRESSION_ALGORITHM = CompressionAlgorithmTags.ZIP;
    private static final char FORMAT_FOR_LITERAL_DATA = PGPLiteralData.BINARY;

    PGPutil() { }

    /**
     * Compresses {@link PGPLiteralData}, writes it to a file
     * and returns it as a byte array
     *
     * @param fileName  {@code String} name of file to which compressed
     *                          {@link PGPLiteralData}  data is written
     * @return {@code byte[]} compressed file as byte array
     * @throws IOException
     */
    public static byte[] compressFile(String fileName) throws IOException
    {
        // Stream to write the literal data to
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        // File which contents are being compressed
        File file = new File(fileName);
        // compress and write data
        PGPCompressedDataGenerator compressedDataGenerator = new PGPCompressedDataGenerator(COMPRESSION_ALGORITHM);
        PGPUtil.writeFileToLiteralData(compressedDataGenerator.open(byteArrayOutputStream),
                FORMAT_FOR_LITERAL_DATA, file);

        compressedDataGenerator.close();
        return byteArrayOutputStream.toByteArray();
    }

    /**
     * Finds a secret key for keyID in {@link PGPSecretKeyRingCollection} and decrypts it.
     * If such key exists the function returns a decrypted private key {@link PGPPrivateKey}
     * null otherwise
     *
     * @param secretKeyRingCollection  {@link PGPSecretKeyRingCollection} to search in
     * @param keyID {@code long}  keyID of the key we are looking for
     * @param passphrase {@code String}  passphrase for secret key decryption
     * @return {@link PGPPrivateKey} or {@code null}
     *          the private key if found or null if no such key found
     * @throws PGPException
     */
    public static PGPPrivateKey findPrivateKey(PGPSecretKeyRingCollection secretKeyRingCollection,
                                              long keyID, String passphrase) throws PGPException {
        // find encrypted private key in the collection
        PGPSecretKey secretKey = secretKeyRingCollection.getSecretKey(keyID);
        if (secretKey != null) {
            PBESecretKeyDecryptor decryptor = new JcePBESecretKeyDecryptorBuilder()
                                                                    .setProvider(PROVIDER)
                                                                    .build(passphrase.toCharArray());
            // decrypt secret key
            PGPPrivateKey privateKey = secretKey.extractPrivateKey(decryptor);
            return privateKey;
        }
        // if no key found return null
        return null;
    }

}
