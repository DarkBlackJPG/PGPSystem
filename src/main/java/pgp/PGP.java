package pgp;

import java.io.*;
import java.security.*;
import java.util.Iterator;

import org.apache.commons.io.FilenameUtils;
import org.apache.log4j.BasicConfigurator;
import org.apache.log4j.Logger;
import org.bouncycastle.bcpg.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.openpgp.operator.PGPContentSigner;
import org.bouncycastle.openpgp.operator.PGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.PublicKeyDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.bc.BcPGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyKeyEncryptionMethodGenerator;
import org.bouncycastle.openpgp.operator.jcajce.*;
import org.bouncycastle.util.io.Streams;
import utility.PGPutil;

/**
 * Unique class with static methods for encryption, decryption, signing and verification
 */
public class PGP
{
    private static final BouncyCastleProvider PROVIDER = new BouncyCastleProvider();
    private static final int SIGNATURE_TYPE = PGPSignature.BINARY_DOCUMENT;
    private static final char FILE_TYPE = PGPLiteralData.BINARY;
    private static final int HASH_TYPE = HashAlgorithmTags.SHA1;
    private static final int ZIP_ALGORITHM = PGPCompressedData.ZIP;
    private static final Logger logger = Logger.getLogger(PGP.class);
    private static PGP pgp;

    static {
        BasicConfigurator.configure();
        Security.addProvider(PROVIDER);
        logger.info("PGP created");
    }


    /**
     * Encrypt the file based on preferences
     *
     * @param fileToEncrypt  path to the {@link File} you wish to encrypt
     * @param publicKeys  array of {@link PGPPublicKey} which you wish to encrypt the data with
     * @param algorithm  algorithm to be used for encryption {@link SymmetricKeyAlgorithmTags}
     * @param compress  if true data will be compressed before encryption using
     *                  {@code ZIP} algorithm {@link CompressionAlgorithmTags}
     * @param radix64  if true encrypted data will be encoded with {@link ArmoredOutputStream}
     * @return {@code String} name of encrypted file
     * @throws IOException
     * @throws PGPException
     */
    public static String encryptFile(String fileToEncrypt,
                                     String originalFile,
                                     PGPPublicKey[] publicKeys,
                                     int algorithm,
                                     boolean radix64,
                                     boolean compress) throws IOException, PGPException {
        logger.info("encryptFile(" + fileToEncrypt + ")");
        // Open new file to which data is written to
        OutputStream outputStream;
        String ext = FilenameUtils.getExtension(fileToEncrypt);
        if (ext.equals("asc") || ext.equals("bpg")) {
            if(radix64) {
                outputStream = new ArmoredOutputStream(new FileOutputStream(fileToEncrypt));
                logger.info("convert to radix64");
            } else {
                outputStream = new BufferedOutputStream(new FileOutputStream(fileToEncrypt));
            }
        } else {
            if(radix64) {
                fileToEncrypt += ".asc";
                outputStream = new ArmoredOutputStream(new FileOutputStream(fileToEncrypt));
                logger.info("convert to radix64");
            } else {
                fileToEncrypt += ".bpg";
                outputStream = new BufferedOutputStream(new FileOutputStream(fileToEncrypt));
            }
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
            byte[] compressedBytes = PGPutil.compressFile(fileToEncrypt).toByteArray();
            encryptedStream = encryptedDataGenerator.open(outputStream, compressedBytes.length);
            encryptedStream.write(compressedBytes);
            logger.info("file compressed");
        } else {
            ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
            // Transform the data from file into PGP literal data and write it to an output stream
            PGPUtil.writeFileToLiteralData(byteArrayOutputStream, FILE_TYPE, new File(fileToEncrypt));
            // Bytes of PGP literal data
            byte[] bytes = byteArrayOutputStream.toByteArray();
            encryptedStream = encryptedDataGenerator.open(outputStream, bytes.length);
            encryptedStream.write(bytes);
        }
        encryptedDataGenerator.close();

        outputStream.flush();
        outputStream.close();
        logger.info("file encrypted");
        return fileToEncrypt;
    }

    /**
     *  Decrypt file with given name
     *
     * @param inputFileName {@code String} for the file to be decrypted
     * @param secretKeyFileName {@code String} for the secret key to be found
     * @param passphrase {@code String} used to decode the {@link PGPSecretKey}
     * @param fileName {@code String} used to make a new decoded {@link File}
     *                       if file name not present in encoded data
     * @return {@code String} name of decrypted file
     * @throws IOException
     */
    public static String decryptFile(String inputFileName,
                               String secretKeyFileName,
                               String passphrase,
                               String fileName) throws IOException, PGPException {
        String outputFileName;
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
            object = pgpObjects.nextObject();
        }
        if (object instanceof PGPEncryptedDataList) {
            encryptedData = (PGPEncryptedDataList)object;
        } else {
            throw new PGPException("bad start of file.");
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
//            if((Object)it.next() instanceof PGPPublicKeyEncryptedData){
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

            outputFileName = literalData.getFileName();
            // If no file name given in input stream set default file name
            if (outputFileName.isBlank()) {
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
        } else if (decryptedObject instanceof PGPOnePassSignatureList) {
            throw new PGPException("signed message - not literal data.");
        } else {
            throw new PGPException("unknown - not literal data.");
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
        return outputFileName;
    }

    /****************************************************************************
     * *        NAPOMENA! Ovde mozemo da prosledimo i secret key ako          * *
     * *        je tako lakse. Trenutno su private i public zbog              * *
     * *        testiranja.                                                   * *
     ****************************************************************************/
    /**
     * Sign file with provided private key
     *
     * @param fileToSign name of the signed {@link File} to sign
     * @param privateKey {@link PGPPrivateKey} used to sign the file
     * @param publicKey {@link PGPPublicKey} used to sign the file
     * @param radix64 if true encrypted data will be encoded with {@link ArmoredOutputStream}
     * @param compress  if true data will be compressed before encryption using
     *                      {@code ZIP} algorithm {@link CompressionAlgorithmTags}
     * @return {@code String} name of signed file
     * @throws IOException
     * @throws PGPException
     */
    public static String signFile(
            String fileToSign,
            PGPPrivateKey privateKey,
            PGPPublicKey publicKey,
            boolean radix64,
            boolean compress) throws IOException,PGPException {
        logger.info("signFile(" + fileToSign + ")");
        OutputStream outputStream;
        if (radix64) {
            fileToSign += ".asc";
            outputStream = new ArmoredOutputStream(new FileOutputStream(fileToSign));
            logger.info("convert to radix64");
        } else {
            fileToSign += ".bpg";
            outputStream = new FileOutputStream(fileToSign);
        }

//        PGPPrivateKey privateKey = secretKey.extractPrivateKey(new JcePBESecretKeyDecryptorBuilder()
//                                                                    .setProvider(PROVIDER)
//                                                                    .build(passphrase.toCharArray()));
        PGPSignatureGenerator signatureGenerator = new PGPSignatureGenerator(
                new JcaPGPContentSignerBuilder(
                        privateKey.getPublicKeyPacket().getAlgorithm(), HASH_TYPE)
                        .setProvider(PROVIDER));

        signatureGenerator.init(SIGNATURE_TYPE, privateKey);

        Iterator<String> it = publicKey.getUserIDs();
        if (it.hasNext()) {
            PGPSignatureSubpacketGenerator signatureSubpacketGenerator = new PGPSignatureSubpacketGenerator();
            signatureSubpacketGenerator.addSignerUserID(false, it.next());
            signatureGenerator.setHashedSubpackets(signatureSubpacketGenerator.generate());
        }



        OutputStream compressedOutputStream = null;
        if(compress) {
            compressedOutputStream =  PGPutil.compressFile(fileToSign);
            // one pass header associated with the current signature
            signatureGenerator.generateOnePassVersion(false)
                            .encode(compressedOutputStream);
            logger.info("file compressed");
        } else {
            // one pass header associated with the current signature
            signatureGenerator.generateOnePassVersion(false)
                                .encode(outputStream);
        }
        File file = new File(fileToSign);
        PGPLiteralDataGenerator literalDataGenerator = new PGPLiteralDataGenerator();
        OutputStream signedOutputStream;
        if(compress){
            signedOutputStream = literalDataGenerator.open(compressedOutputStream,
                    FILE_TYPE,
                    file);
        } else {
            signedOutputStream = literalDataGenerator.open(outputStream,
                    FILE_TYPE,
                    file);
        }
        FileInputStream fileInputStream = new FileInputStream(file);
        byte[] fileBytes = fileInputStream.readAllBytes();

        signedOutputStream.write(fileBytes);
        signatureGenerator.update(fileBytes);

        literalDataGenerator.close();

        if(compress) {
            signatureGenerator.generate().encode(compressedOutputStream);
        } else {
            signatureGenerator.generate().encode(outputStream);
        }

        outputStream.flush();
        outputStream.close();
        fileInputStream.close();
        logger.info("file signed");
        return fileToSign;
    }

    /**
     * Verify signature for the specified file
     *
     * @param fileToVerify name of the signed {@link File} to verify
     * @param publicKeyFileName {@code String} for the public key to be found
     * @return {@code boolean} true if file is verified, false otherwise
     * @throws IOException
     * @throws PGPException
     */
    public static boolean verifyFile(String fileToVerify,
                                  String publicKeyFileName) throws IOException, PGPException {

        InputStream fileInputStream = PGPUtil.getDecoderStream(new BufferedInputStream(new FileInputStream(fileToVerify)));

        PGPObjectFactory objectFactory = new PGPObjectFactory(fileInputStream, new JcaKeyFingerprintCalculator());
        Object object = objectFactory.nextObject();
        if(object instanceof PGPCompressedData) {
            objectFactory = new PGPObjectFactory(((PGPCompressedData) object).getDataStream(),
                    new JcaKeyFingerprintCalculator());
            object = objectFactory.nextObject();
        }

        PGPOnePassSignatureList onePassSignatureList = (PGPOnePassSignatureList) object;
        PGPOnePassSignature onePassSignature = onePassSignatureList.get(0);

        PGPLiteralData literalData = (PGPLiteralData)objectFactory.nextObject();


        PGPPublicKeyRingCollection  publicKeyRingCollection = new PGPPublicKeyRingCollection(
                                            PGPUtil.getDecoderStream(new FileInputStream(publicKeyFileName)),
                                            new JcaKeyFingerprintCalculator());

        PGPPublicKey publicKey = publicKeyRingCollection.getPublicKey(onePassSignature.getKeyID());
        FileOutputStream fileOutputStream = new FileOutputStream(literalData.getFileName());

        onePassSignature.init(new JcaPGPContentVerifierBuilderProvider()
                                    .setProvider(PROVIDER),
                              publicKey);


        byte[] bytes = literalData.getInputStream().readAllBytes();
        onePassSignature.update(bytes);
        fileOutputStream.write(bytes);

        fileOutputStream.flush();
        fileOutputStream.close();

        PGPSignatureList signatureList = (PGPSignatureList)objectFactory.nextObject();

        if (onePassSignature.verify(signatureList.get(0))) {
            logger.info("signature verified.");
            return true;
        } else {
            logger.info("signature verification failed.");
            return false;
        }
    }


    public static String signAndEncrypt(String fileToSign,
                                        PGPPrivateKey privateKey,
                                        PGPPublicKey[] publicKeys,
                                        int algorithm,
                                        boolean radix64,
                                        boolean compress) throws IOException,PGPException {
        logger.info("signFile(" + fileToSign + ")");
        OutputStream outputStream;
        String signedFile = fileToSign;
        if (radix64) {
            signedFile += ".asc";
            outputStream = new ArmoredOutputStream(new FileOutputStream(signedFile));
            logger.info("convert to radix64");
        } else {
            signedFile += ".bpg";
            outputStream = new FileOutputStream(signedFile);
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

//        PGPPrivateKey privateKey = secretKey.extractPrivateKey(new JcePBESecretKeyDecryptorBuilder()
//                                                                    .setProvider(PROVIDER)
//                                                                    .build(passphrase.toCharArray()));
        PGPSignatureGenerator signatureGenerator = new PGPSignatureGenerator(
                new JcaPGPContentSignerBuilder(
                        privateKey.getPublicKeyPacket().getAlgorithm(), HASH_TYPE)
                        .setProvider(PROVIDER));

        signatureGenerator.init(SIGNATURE_TYPE, privateKey);

        Iterator<String> it = publicKeys[0].getUserIDs();
        if (it.hasNext()) {
            PGPSignatureSubpacketGenerator signatureSubpacketGenerator = new PGPSignatureSubpacketGenerator();
            signatureSubpacketGenerator.addSignerUserID(false, it.next());
            signatureGenerator.setHashedSubpackets(signatureSubpacketGenerator.generate());
        }


        OutputStream encryptedStream;
        ByteArrayOutputStream byteArrayOutputStream;
        byte[] bytes;
        File file = new File(fileToSign);
        FileInputStream fileInputStream = new FileInputStream(file);
        // Stream with which encrypted data is written to an output stream
        if(compress) {
            byteArrayOutputStream = PGPutil.compressFile(fileToSign);
            bytes = byteArrayOutputStream.toByteArray();
            encryptedStream = encryptedDataGenerator.open(outputStream, bytes.length);
            // one pass header associated with the current signature
            signatureGenerator.generateOnePassVersion(false)
                    .encode(byteArrayOutputStream);
            logger.info("file compressed");
        } else {
            byteArrayOutputStream = new ByteArrayOutputStream();
            // Transform the data from file into PGP literal data and write it to an output stream
            PGPUtil.writeFileToLiteralData(byteArrayOutputStream, FILE_TYPE, file);
            // Bytes of PGP literal data
            bytes = byteArrayOutputStream.toByteArray();
            // one pass header associated with the current signature
            signatureGenerator.generateOnePassVersion(false)
                    .encode(outputStream);
            encryptedStream = encryptedDataGenerator.open(outputStream, bytes.length);
        }
        signatureGenerator.update(fileInputStream.readAllBytes());

        if(compress) {
            signatureGenerator.generate().encode(byteArrayOutputStream);
        } else {
            signatureGenerator.generate().encode(outputStream);
        }

        encryptedStream.write(bytes);
        encryptedDataGenerator.close();
        outputStream.flush();
        outputStream.close();

        logger.info("file " + fileToSign + " signed and encrypted");
        return signedFile;
    }

    public static boolean decryptAndVerify(String inputFileName,
                                           String secretKeyFileName,
                                           String publicKeyFileName,
                                           String passphrase,
                                           String fileName) throws IOException, PGPException {
        String outputFileName;
        logger.info("decryptFile(" + inputFileName + ")");
        InputStream fileInput = new BufferedInputStream(new FileInputStream(inputFileName));
        InputStream secretKeyInput = new BufferedInputStream(new FileInputStream(secretKeyFileName));
        InputStream publicKeyInput = new BufferedInputStream(new FileInputStream(publicKeyFileName));

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


        if(object instanceof PGPCompressedData) {
            pgpObjects = new PGPObjectFactory(((PGPCompressedData) object).getDataStream(),
                    new JcaKeyFingerprintCalculator());
            object = pgpObjects.nextObject();
        }
        PGPOnePassSignature onePassSignature;
        if(object instanceof PGPOnePassSignatureList) {
            PGPOnePassSignatureList onePassSignatureList = (PGPOnePassSignatureList) object;
            onePassSignature = onePassSignatureList.get(0);
            object = pgpObjects.nextObject();

        } else {
            throw new PGPException("bad start of file.");
        }

        PGPLiteralData literalData = (PGPLiteralData)object;


        PGPPublicKeyRingCollection  publicKeyRingCollection = new PGPPublicKeyRingCollection(
                PGPUtil.getDecoderStream(new FileInputStream(publicKeyFileName)),
                new JcaKeyFingerprintCalculator());

        PGPPublicKey publicKey = publicKeyRingCollection.getPublicKey(onePassSignature.getKeyID());
        FileOutputStream fileOutputStream = new FileOutputStream(literalData.getFileName());

        onePassSignature.init(new JcaPGPContentVerifierBuilderProvider()
                        .setProvider(PROVIDER),
                publicKey);


        byte[] bytes = literalData.getInputStream().readAllBytes();
        onePassSignature.update(bytes);
        PGPSignatureList signatureList = (PGPSignatureList)pgpObjects.nextObject();

        if (onePassSignature.verify(signatureList.get(0))) {
            logger.info("signature verified.");
            return true;
        } else {
            logger.info("signature verification failed.");
            return false;
        }
    }

}