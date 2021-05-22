package utility;

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











    /**
     * A simple routine that opens a key ring file and loads the first available key
     * suitable for encryption.
     *
     * @param inputStream {@link InputStream} to search in containing the public key data
     * @return the first public key found.
     * @throws IOException
     * @throws PGPException
     */
    public static PGPPublicKey readPublicKey(InputStream inputStream) throws IOException, PGPException
    {
        PGPPublicKeyRingCollection publicKeyRingCollection = new PGPPublicKeyRingCollection(
                PGPUtil.getDecoderStream(inputStream), new JcaKeyFingerprintCalculator());

        //
        // we just loop through the collection till we find a key suitable for encryption, in the real
        // world you would probably want to be a bit smarter about this.
        Iterator<PGPPublicKeyRing> keyRingIter = publicKeyRingCollection.getKeyRings();
        while (keyRingIter.hasNext())
        {
            PGPPublicKeyRing keyRing = (PGPPublicKeyRing)keyRingIter.next();

            Iterator<PGPPublicKey> keyIter = keyRing.getPublicKeys();
            while (keyIter.hasNext())
            {
                PGPPublicKey key = (PGPPublicKey)keyIter.next();

                if (key.isEncryptionKey())
                {
                    return key;
                }
            }
        }

        throw new IllegalArgumentException("Can't find encryption key in key ring.");
    }

    /**
     * A simple routine that opens a key ring file and loads the first available key
     * suitable for signature generation.
     *
     * @param input stream to read the secret key ring collection from.
     * @return a secret key.
     * @throws IOException on a problem with using the input stream.
     * @throws PGPException if there is an issue parsing the input stream.
     */
    public static PGPSecretKey readSecretKey(InputStream input) throws IOException, PGPException
    {
        PGPSecretKeyRingCollection pgpSec = new PGPSecretKeyRingCollection(
                PGPUtil.getDecoderStream(input), new JcaKeyFingerprintCalculator());

        //
        // we just loop through the collection till we find a key suitable for encryption, in the real
        // world you would probably want to be a bit smarter about this.
        //

        Iterator<PGPSecretKeyRing> keyRingIter = pgpSec.getKeyRings();
        while (keyRingIter.hasNext())
        {
            PGPSecretKeyRing keyRing = (PGPSecretKeyRing)keyRingIter.next();

            Iterator<PGPSecretKey> keyIter = keyRing.getSecretKeys();
            while (keyIter.hasNext())
            {
                PGPSecretKey key = (PGPSecretKey)keyIter.next();

                if (key.isSigningKey())
                {
                    return key;
                }
            }
        }

        throw new IllegalArgumentException("Can't find signing key in key ring.");
    }
}
