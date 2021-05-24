package pgp;

import java.io.*;
import java.security.*;
import java.util.Iterator;

import org.apache.log4j.BasicConfigurator;
import org.apache.log4j.Logger;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.CompressionAlgorithmTags;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.PublicKeyDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.jcajce.*;
import org.bouncycastle.util.io.Streams;
import utility.PGPutil;

/**
 * Unique class with static methods for encryption, decryption, signing and verification
 */
public class PGP
{
    private static final BouncyCastleProvider PROVIDER = new BouncyCastleProvider();
    private final static Logger logger = Logger.getLogger(PGP.class);
    private static PGP pgp;

    private PGP(Provider p) {
        BasicConfigurator.configure();
        Security.addProvider(p);
        logger.info("PGP created");
    }

    public static PGP getInstancePGP(){
        if(pgp == null) {
            pgp = new PGP(PROVIDER);
        }
        logger.info("PGP returned");
        return pgp;
    }

    /**
     *  Decrypt file with given name
     *
     * @param inputFileName {@code String} for the file to be decrypted
     * @param secretKeyFileName {@code String} for the secret key to be found
     * @param passphrase {@code String} used to decode the {@link PGPSecretKey}
     * @param fileName {@code String} used to make a new decoded {@link File}
     *                       if file name not present in encoded data
     * @throws IOException
     */
    public void decryptFile(String inputFileName,
                                   String secretKeyFileName,
                                   String passphrase,
                                   String fileName) throws IOException, PGPException {

        logger.info("decryptFile(" + inputFileName + ")");
        InputStream fileInput = new BufferedInputStream(new FileInputStream(inputFileName));
        InputStream keyInput = new BufferedInputStream(new FileInputStream(secretKeyFileName));

        // Read PGP data from the provided stream i.e. file input stream and
        // construct an object factory to read PGP objects
        PGPObjectFactory pgpObjects = new PGPObjectFactory(PGPUtil.getDecoderStream(fileInput),
                                            new JcaKeyFingerprintCalculator());
        Object object = pgpObjects.nextObject();

        // A holder for a list of PGP encryption method packets (PGP encrypted data objects)
        // and the encrypted data associated with them
        PGPEncryptedDataList encryptedData;

        // If the first object is a PGP marker packet we have to skip it
        // see https://datatracker.ietf.org/doc/html/rfc4880#section-5.8 for further explanation
        if (object instanceof PGPMarker) {
            encryptedData = (PGPEncryptedDataList)pgpObjects.nextObject();
        } else {
            encryptedData = (PGPEncryptedDataList)object;
        }

        // Read an entire secret key file and build a PGPSecretKeyRingCollection
        // from the passed input stream
        PGPSecretKeyRingCollection secretKeyRingCollection = new PGPSecretKeyRingCollection(
                PGPUtil.getDecoderStream(keyInput), new JcaKeyFingerprintCalculator());

        // see if the message is for me  :)
        PGPPrivateKey privateKey = null;
        PGPPublicKeyEncryptedData publicKeyEncryptedData = null;
        // Iterate over the PGP encrypted data objects in order in which they appeared in the input stream
        for(Iterator<PGPEncryptedData> it = encryptedData.iterator();
            privateKey == null && it.hasNext();) {
            // Encrypted data with key data for the public key used to encrypt it
//            if(it.next() instanceof PGPPublicKeyEncryptedData){
                publicKeyEncryptedData = (PGPPublicKeyEncryptedData)it.next();
                // until the private key found or reached the end of the stream
                privateKey = PGPutil.findPrivateKey(secretKeyRingCollection,
                                publicKeyEncryptedData.getKeyID(), passphrase);
//            }
        }
        // message not for me :(
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
            PGPObjectFactory decompressedObjects = new PGPObjectFactory(compressedData.getDataStream(),
                                                                new JcaKeyFingerprintCalculator());
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

            Streams.pipeAll(literalDataInputStream, BufferedFileOutputStream);


            BufferedFileOutputStream.close();
            literalDataInputStream.close();
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
                logger.info("PGPPublicKeyEncryptedData passed integrity check");
            }
        } else {
            logger.info("PGPPublicKeyEncryptedData no integrity check");
        }
    }


    /**
     * Encrypt the file based on preferences
     *
     * @param encryptedFileName  path to the {@link File} you wish the data to be written to
     * @param fileToEncrypt  path to the {@link File} you wish to encrypt
     * @param publicKeys  array of {@link PGPPublicKey} which you wish to encrypt the data with
     * @param algorithm  algorithm to be used for encryption {@link SymmetricKeyAlgorithmTags}
     * @param compress  if true data will be compressed before encryption using
     *                  ZIP algorithm {@link CompressionAlgorithmTags}
     * @param radix64  if true encrypted data will be encoded with {@link ArmoredOutputStream}
     * @throws IOException
     * @throws PGPException
     */
    public void encryptFile(String encryptedFileName,
                               String fileToEncrypt,
                               PGPPublicKey[] publicKeys,
                               int algorithm,
                               boolean compress,
                               boolean radix64) throws IOException, PGPException {
        logger.info("encryptFile(" + fileToEncrypt + ")");

        // Open new file to which data is written to
        OutputStream outputStream;

        if(radix64) {
            outputStream = new ArmoredOutputStream(new FileOutputStream(encryptedFileName));
            logger.info("convert to radix64");
        } else {
            outputStream = new BufferedOutputStream(new FileOutputStream(encryptedFileName));
        }
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
        logger.info("public keys added");

        OutputStream encryptedStream;
        // Stream with which encrypted data is written to an output stream
        if(compress) {
            byte[] compressedBytes = PGPutil.compressFile(fileToEncrypt);
            encryptedStream = encryptedDataGenerator.open(outputStream, compressedBytes.length);
            encryptedStream.write(compressedBytes);
            logger.info("file compressed");
        } else {
            ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
            // Transform the data from file into PGP literal data and write it to an output stream
            PGPUtil.writeFileToLiteralData(byteArrayOutputStream, PGPLiteralData.BINARY, new File(fileToEncrypt));
            // Bytes of PGP literal data
            byte[] bytes = byteArrayOutputStream.toByteArray();
            encryptedStream = encryptedDataGenerator.open(outputStream, bytes.length);
            encryptedStream.write(bytes);
        }
        encryptedDataGenerator.close();

        outputStream.flush();
        outputStream.close();
        logger.info("file encrypted");
    }


}