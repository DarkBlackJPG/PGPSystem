package pgp;

import java.io.*;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Iterator;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.CompressionAlgorithmTags;
import org.bouncycastle.bcpg.PacketTags;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.openpgp.operator.PublicKeyDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyDataDecryptorFactoryBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyKeyEncryptionMethodGenerator;
import org.bouncycastle.util.encoders.UrlBase64Encoder;
import org.bouncycastle.util.io.Streams;
import utility.PGPutil;


public class PGP
{
    private static final String PROVIDER = "BC";
    private static final BouncyCastleProvider provider = new BouncyCastleProvider();
    private static PGP pgp;

    private PGP(java.security.Provider p) {
        Security.addProvider(p);
    }

    public static PGP getInstancePGP(){
        if(pgp == null) {
            pgp = new PGP(provider);
        }
        return pgp;
    }

    /**
     *  Decrypt file from input stream
     *
     * @param inputFileName {@code String} for the file to be decrypted
     * @param keyFileName {@code String} for the secret key to be found
     * @param passphrase {@code String} used to decode the {@code PGPPrivateKey}
     * @param fileName {@code String} used to make a new decoded {@code File}
     * @throws IOException
     */
    public static void decryptFile(String inputFileName,
                                   String keyFileName,
                                   String passphrase,
                                   String fileName) throws IOException, PGPException {
        InputStream fileInput = new BufferedInputStream(new FileInputStream(inputFileName));
        InputStream keyInput = new BufferedInputStream(new FileInputStream(keyFileName));
        // Read PGP data from the provided stream i.e. file input stream
        fileInput = PGPUtil.getDecoderStream(fileInput);

        // Construct an object factory to read PGP objects from a stream
        // in this case /*PGP encrypted data objects*/
        PGPObjectFactory pgpObjects = new PGPObjectFactory(fileInput, new JcaKeyFingerprintCalculator());

        // A holder for a list of PGP encryption method packets (PGP encrypted data objects)
        // and the encrypted data associated with them
        PGPEncryptedDataList encryptedData;

        // If the first object is a PGP marker packet we have to skip it
        // see https://datatracker.ietf.org/doc/html/rfc4880#section-5.8 for further explanation
        Object object = pgpObjects.nextObject();
        if (object instanceof PGPMarker) {
            encryptedData = (PGPEncryptedDataList)pgpObjects.nextObject();
        } else {
            encryptedData = (PGPEncryptedDataList)object;
        }

        // Read an entire secret key file and build a PGPSecretKeyRingCollection
        // from the passed input stream
        PGPSecretKeyRingCollection  secretKeyRingCollection = new PGPSecretKeyRingCollection(
                PGPUtil.getDecoderStream(keyInput), new JcaKeyFingerprintCalculator());

        // Decrypted private key
        PGPPrivateKey privateKey = null;
        PGPPublicKeyEncryptedData publicKeyEncryptedData = null;
        // Iterate over the PGP encrypted data objects in order in which they appeared in the input stream
        for(Iterator<PGPEncryptedData> it = encryptedData.getEncryptedDataObjects();
            privateKey == null && it.hasNext();
            it.next()) {
            // Encrypted data with key data for the public key used to encrypt it
            publicKeyEncryptedData = (PGPPublicKeyEncryptedData)it;
            // until the private key found or reached the end of the stream
            privateKey = PGPutil.findPrivateKey(secretKeyRingCollection,
                            publicKeyEncryptedData.getKeyID(), passphrase);
        }
        if (privateKey == null) {
            throw new IllegalArgumentException("Secret key not found. " +
                    "Wrong PGPSecretKeyRingCollection or PGPPublicKeyEncryptedData");
        }

        PublicKeyDataDecryptorFactory decryptor = new JcePublicKeyDataDecryptorFactoryBuilder()
                                                                    .setProvider(PROVIDER)
                                                                    .build(privateKey);

        // Decrypted input stream
        InputStream decrypted = publicKeyEncryptedData.getDataStream(decryptor);
        // PGP decrypted data objects using privateKey
        PGPObjectFactory decryptedObjects = new PGPObjectFactory(decrypted, new JcaKeyFingerprintCalculator());
        Object decryptedObject = decryptedObjects.nextObject();

        // First decompress if necessary
        if (decryptedObject instanceof PGPCompressedData) {
            PGPCompressedData compressedData = (PGPCompressedData)decryptedObject;
            PGPObjectFactory decompressedObjects = new PGPObjectFactory(compressedData.getDataStream(), new JcaKeyFingerprintCalculator());
            decryptedObject = decompressedObjects.nextObject();
        }
        // Read data
        if (decryptedObject instanceof PGPLiteralData) {
            PGPLiteralData literalData = (PGPLiteralData)decryptedObject;

            String outputFileName = literalData.getFileName();
            // If no file name given in input stream set default file name
            if (outputFileName.equals("")) {
                outputFileName = fileName;
            }
            // File to which data is to be written in
            FileOutputStream fileOutputStream = new FileOutputStream(outputFileName);
            OutputStream BufferedFileOutputStream = new BufferedOutputStream(fileOutputStream);
            // Decrypted and decompressed data ready to be read
            InputStream literalDataInputStream = literalData.getInputStream();
//PGPUtil.getDecoderStream()
            Streams.pipeAll(literalDataInputStream, BufferedFileOutputStream);

            fileOutputStream.close();
        }
        else if (decryptedObject instanceof PGPOnePassSignatureList) {
            throw new PGPException("signed message - not literal data.");
        } else {
            throw new PGPException("not literal data - unknown.");
        }

        if (publicKeyEncryptedData.isIntegrityProtected()) {
            if (!publicKeyEncryptedData.verify()) {
                throw new VerifyError("message failed integrity check");
            } else {
                // passed integrity check
            }
        } else {
            // no integrity check
        }
    }


    /**
     * Encrypt the file based on preferences
     *
     * @param encryptedFileName  path to the {@link File} you wish the data to be written to
     * @param fileToEncrypt  path to the {@link File} you wish to encrypt
     * @param publicKeys  array of {@PGPPublicKey} which you wish to encrypt the data with
     * @param algorithm  algorithm to be used for encryption
     * @param compress  if true data will be compressed before encryption using
     *                  {@link CompressionAlgorithmTags} algorithm
     * @param radix64  if true encrypted data will be encoded with {@link UrlBase64Encoder}
     * @return void
     * @throws IOException
     * @throws PGPException
     */
    public static void encryptFile(String encryptedFileName,
                                   String fileToEncrypt,
                                   PGPPublicKey[] publicKeys,
                                   int algorithm,
                                   boolean compress,
                                   boolean radix64) throws IOException, PGPException {

        // Open new file to which data is written to
        OutputStream armouredOutputStream = new ArmoredOutputStream(new FileOutputStream(encryptedFileName));

        // Make new encryptor
        PGPEncryptedDataGenerator encryptedDataGenerator = new PGPEncryptedDataGenerator(
                                        new JcePGPDataEncryptorBuilder(algorithm)
                                                .setWithIntegrityPacket(true)
                                                .setSecureRandom(new SecureRandom())
                                                .setProvider(PROVIDER));

        // Add all recipients who will be able to see this message
        for (PGPPublicKey publicKey: publicKeys) {
            encryptedDataGenerator.addMethod(new JcePublicKeyKeyEncryptionMethodGenerator(publicKey)
                                                    .setProvider(PROVIDER));
        }

        OutputStream encryptedStream;
        // Stream with which encrypted data is written to an output stream
        if(compress) {
            byte[] compressedBytes = PGPutil.compressFile(fileToEncrypt);
            if(radix64){
                // Stream to write encrypted packets to from which byte array is read
                ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
                encryptedStream = encryptedDataGenerator.open(byteArrayOutputStream, compressedBytes.length);
                encryptedStream.write(compressedBytes);
                UrlBase64Encoder radix64Encoder = new UrlBase64Encoder();
                radix64Encoder.encode(byteArrayOutputStream.toByteArray(), 0,
                        byteArrayOutputStream.size(), armouredOutputStream);
            } else {
                encryptedStream = encryptedDataGenerator.open(armouredOutputStream, compressedBytes.length);
                encryptedStream.write(compressedBytes);
            }
        } else {
            ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
            // Transform the data from file into PGP literal data and write it to an output stream
            PGPUtil.writeFileToLiteralData(byteArrayOutputStream, PGPLiteralData.BINARY, new File(fileToEncrypt));
            // Bytes of PGP literal data
            byte[] bytes = byteArrayOutputStream.toByteArray();
            if(radix64){
                encryptedStream = encryptedDataGenerator.open(byteArrayOutputStream, bytes.length);
                encryptedStream.write(bytes);
                UrlBase64Encoder radix64Encoder = new UrlBase64Encoder();
                radix64Encoder.encode(byteArrayOutputStream.toByteArray(), 0,
                                      byteArrayOutputStream.size(), armouredOutputStream);
            } else {
                encryptedStream = encryptedDataGenerator.open(armouredOutputStream, bytes.length);
                encryptedStream.write(bytes);
            }
        }
        encryptedDataGenerator.close();

        armouredOutputStream.close();
    }

    public static void main( String[] args) {
        try {

        } catch (Exception e){
            System.out.println(e);
        }
    }
}