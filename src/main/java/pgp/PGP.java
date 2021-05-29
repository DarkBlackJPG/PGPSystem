package pgp;

import java.io.*;
import java.security.*;
import java.util.Date;
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
    private static final int BUFFER_SIZE = 256;

    static {
        BasicConfigurator.configure();
        Security.addProvider(PROVIDER);
        logger.info("PGP created");
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
    public static void decryptFile(String inputFileName,
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

            String outputFileName = literalData.getFileName();
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
     * @return {@code String} name of encrypted {@link File}
     * @throws IOException
     * @throws PGPException
     */
    public static String encryptFile(String fileToEncrypt,
                                   PGPPublicKey[] publicKeys,
                                   int algorithm,
                                   boolean compress,
                                   boolean radix64) throws IOException, PGPException {
        logger.info("encryptFile(" + fileToEncrypt + ")");

        // Open new file to which data is written to
        OutputStream outputStream;

        if(radix64) {
            fileToEncrypt += ".asc";
            outputStream = new ArmoredOutputStream(new FileOutputStream(fileToEncrypt));
            logger.info("convert to radix64");
        } else {
            fileToEncrypt += ".bpg";
            outputStream = new BufferedOutputStream(new FileOutputStream(fileToEncrypt));
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
        return fileToEncrypt;
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
                                     String publicKeyFileName) throws IOException, PGPException, SignatureException {

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
            throw new SignatureException("Signature verification failed");
//            return false;
        }
    }

    /**
     * Sign file with provided private key
     *
     * @param fileToSign name of the signed {@link File} to sign
     * @param privateKey {@link PGPPrivateKey} used to sign the file
     * @param publicKey {@link PGPPublicKey} used to sign the file
     * @param radix64 if true encrypted data will be encoded with {@link ArmoredOutputStream}
     * @param compress  if true data will be compressed before encryption using
     *                      {@code ZIP} algorithm {@link CompressionAlgorithmTags}
     * @return {@code String} name of signed {@link File}
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
        String fileName = fileToSign;
        OutputStream outputStream;
        if (radix64) {
            fileName += ".asc";
            outputStream = new ArmoredOutputStream(new FileOutputStream(fileName));
            logger.info("convert to radix64");
        } else {
            fileName += ".bpg";
            outputStream = new FileOutputStream(fileName);
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
        PGPCompressedDataGenerator compressedDataGenerator = null;
        OutputStream compressedOutputStream = null;
        if(compress) {
            compressedDataGenerator = new PGPCompressedDataGenerator(ZIP_ALGORITHM);
            compressedOutputStream =  new BCPGOutputStream(compressedDataGenerator.open(outputStream));
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
            compressedDataGenerator.close();
        } else {
            signatureGenerator.generate().encode(outputStream);
        }

        outputStream.flush();
        outputStream.close();
        logger.info("file signed");
        return fileName;
    }

    public static String signAndEncrypt(String fileToSign,
                                        PGPPrivateKey privateKey,
                                        PGPPublicKey publicKey,
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
        for (PGPPublicKey pKey: publicKeys) {
            encryptedDataGenerator.addMethod(new JcePublicKeyKeyEncryptionMethodGenerator(pKey)
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

        Iterator<String> it = publicKey.getUserIDs();
        if (it.hasNext()) {
            PGPSignatureSubpacketGenerator signatureSubpacketGenerator = new PGPSignatureSubpacketGenerator();
            signatureSubpacketGenerator.addSignerUserID(false, it.next());
            signatureGenerator.setHashedSubpackets(signatureSubpacketGenerator.generate());
        }


        OutputStream compressedStream = null;
        OutputStream finalOutputStream = null;
        File file = new File(fileToSign);
        byte[] fileBytes = new FileInputStream(file).readAllBytes();
        OutputStream encryptedStream = encryptedDataGenerator
                                            .open(outputStream, new byte[BUFFER_SIZE]);
        // Stream with which encrypted data is written to an output stream
        if(compress) {
            compressedStream =  new PGPCompressedDataGenerator(ZIP_ALGORITHM)
                                .open(encryptedStream, new byte[BUFFER_SIZE]);
            signatureGenerator.generateOnePassVersion(true)
                    .encode(compressedStream);
            finalOutputStream = new PGPLiteralDataGenerator()
                    .open(compressedStream, FILE_TYPE,
                            signedFile, new Date(file.lastModified()),
                            new byte[BUFFER_SIZE]);
//            PGPUtil.writeFileToLiteralData(compressedStream, FILE_TYPE, file, new byte[BUFFER_SIZE]);
            logger.info("file compressed");
        } else {
            signatureGenerator.generateOnePassVersion(true)
                    .encode(encryptedStream);
            PGPUtil.writeFileToLiteralData(encryptedStream, FILE_TYPE, file, new byte[BUFFER_SIZE]);
        }

        finalOutputStream.write(fileBytes, 0, fileBytes.length);
        signatureGenerator.update(fileBytes);

        finalOutputStream.flush();
        finalOutputStream.close();
        if(compress) {
            signatureGenerator.generate().encode(compressedStream);
        } else {
            signatureGenerator.generate().encode(encryptedStream);
        }

        compressedStream.flush();
        compressedStream.close();

        encryptedStream.flush();
        encryptedStream.close();

        outputStream.flush();
        outputStream.close();
        logger.info("file " + fileToSign + " signed and encrypted");
        return signedFile;
    }

    public static boolean decryptAndVerify(String inputFileName,
                                           String secretKeyFileName,
                                           String publicKeyFileName,
                                           String passphrase) throws IOException, PGPException, SignatureException {
        logger.info("decryptFile(" + inputFileName + ")");
        InputStream fileInput = new BufferedInputStream(new FileInputStream(inputFileName));
        InputStream secretKeyInput = new BufferedInputStream(new FileInputStream(secretKeyFileName));
        InputStream publicKeyInput = new BufferedInputStream(new FileInputStream(publicKeyFileName));

        PGPObjectFactory pgpObjects = new PGPObjectFactory(PGPUtil.getDecoderStream(fileInput),
                new JcaKeyFingerprintCalculator());
        Object object = pgpObjects.nextObject();
        PGPEncryptedDataList encryptedData = null;
        PGPOnePassSignatureList onePassSignatureList = null;
        if (object instanceof PGPMarker) {
            encryptedData = (PGPEncryptedDataList) pgpObjects.nextObject();
        } else if (object instanceof PGPEncryptedDataList) {
            encryptedData = (PGPEncryptedDataList) object;
        } else {
            throw new  PGPException("message unknown message type. bad start");
        }

        PGPSecretKeyRingCollection secretKeyRingCollection = new PGPSecretKeyRingCollection(
                PGPUtil.getDecoderStream(secretKeyInput), new JcaKeyFingerprintCalculator());

        // see if the message is for me  :)
        PGPPrivateKey privateKey = null;
        PGPPublicKeyEncryptedData publicKeyEncryptedData = null;

        for (Iterator<PGPEncryptedData> it = encryptedData.iterator();
             privateKey == null && it.hasNext(); ) {

            publicKeyEncryptedData = (PGPPublicKeyEncryptedData) it.next();

            privateKey = PGPutil.findPrivateKey(secretKeyRingCollection,
                    publicKeyEncryptedData.getKeyID(), passphrase);
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
        pgpObjects = new PGPObjectFactory(decrypted, new JcaKeyFingerprintCalculator());
        object = pgpObjects.nextObject();


        PGPSignatureList signatureList = null;
        PGPLiteralData literalData = null;
        byte[] bytes = null;

        while (object != null) {
            if (object instanceof PGPCompressedData) {
                PGPCompressedData compressedData = (PGPCompressedData) object;
                pgpObjects = new PGPObjectFactory(compressedData.getDataStream(),
                        new JcaKeyFingerprintCalculator());
                object = pgpObjects.nextObject();
            }

            if (object instanceof PGPLiteralData) {
                literalData = (PGPLiteralData) object;
                bytes = literalData.getInputStream().readAllBytes();
            } else if (object instanceof PGPOnePassSignatureList) {
                onePassSignatureList = (PGPOnePassSignatureList) object;
            } else if (object instanceof PGPSignatureList) {
                signatureList = (PGPSignatureList) object;
            } else {
                logger.info("signature verification failed.");
                throw new PGPException("message unknown message type.");
            }
            object = pgpObjects.nextObject();
        }

        if (onePassSignatureList == null || signatureList == null) {
            logger.info("signature verification failed.");
            throw new PGPException("Poor PGP. Signatures not found.");
        } else {

            PGPOnePassSignature onePassSignature = onePassSignatureList.get(0);
            PGPPublicKeyRingCollection  publicKeyRingCollection = new PGPPublicKeyRingCollection(
                    PGPUtil.getDecoderStream(publicKeyInput), new JcaKeyFingerprintCalculator());

            PGPPublicKey publicKey = publicKeyRingCollection.getPublicKey(onePassSignature.getKeyID());

            if (publicKey != null && literalData != null) {
                onePassSignature.init(new JcaPGPContentVerifierBuilderProvider().setProvider("BC"), publicKey);
                FileOutputStream fileOutputStream = new FileOutputStream(literalData.getFileName());

                onePassSignature.init(new JcaPGPContentVerifierBuilderProvider()
                                .setProvider(PROVIDER),
                        publicKey);

                onePassSignature.update(bytes);
                fileOutputStream.write(bytes);
                fileOutputStream.flush();
                fileOutputStream.close();
                if (onePassSignature.verify(signatureList.get(0))) {
                    logger.info("signature verified.");
                    return true;
                } else {
                    logger.info("signature verification failed.");
                    throw new SignatureException("Signature verification failed");
//                    return false;
                }
            }

        }
        return true;
    }

}