package pgp;

import org.apache.log4j.BasicConfigurator;
import org.apache.log4j.Logger;
import org.bouncycastle.bcpg.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.PublicKeyDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.jcajce.*;
import org.bouncycastle.util.io.Streams;
import utility.KeyManager.KeyringManager;
import utility.PGPutil;
import utility.helper.EncryptionWrapper;

import java.io.*;
import java.security.SecureRandom;
import java.security.Security;
import java.security.SignatureException;
import java.util.ArrayList;
import java.util.Date;
import java.util.Iterator;

/**
 * Class with static methods for encryption, decryption, signing and verification.
 * As well as signing + encryption and decryption + verification.
 */
public class PGP {
    private static final BouncyCastleProvider PROVIDER = new BouncyCastleProvider();
    private static final int SIGNATURE_TYPE = PGPSignature.BINARY_DOCUMENT;
    private static final char FILE_TYPE = PGPLiteralData.BINARY;
    private static final int HASH_TYPE = HashAlgorithmTags.SHA1;
    private static final int ZIP_ALGORITHM = PGPCompressedData.ZIP;
    private static final Logger logger = Logger.getLogger(PGP.class);
    private static final int BUFFER_SIZE = 256;
    private static final String publicKeyFile = KeyringManager.publicKeyFile;
    private static final String privateKeyFile = KeyringManager.privateKeyFile;

    static {
        BasicConfigurator.configure();
        Security.addProvider(PROVIDER);
        logger.info("PGP created");
    }

    /**
     * Encrypt and/or sign the file based on preferences
     *
     * @param sign  if true sign file using {@code signKeyID}, otherwise no effect
     * @param encrypt  if true encrypt file using {@code data}, otherwise no effect
     * @param radix64  if true encrypted data will be encoded with {@link ArmoredOutputStream}
     * @param compress  if true data will be compressed before encryption using
     *                  {@code ZIP} algorithm {@link CompressionAlgorithmTags}
     * @param algorithm  algorithm to be used for encryption {@link SymmetricKeyAlgorithmTags}
     * @param data  {@link EncryptionWrapper} data of public keys for encryption
     * @param fileLocation  path to the {@link File} you wish to encrypt and/or sign
     * @param signKeyID  ID of key used to sign the given file
     * @param passphrase  password used to extract {@link PGPPrivateKey} for signature
     * @throws PGPException
     * @throws IOException
     * @throws IllegalArgumentException
     */
    public static void signatureAndEncryption(boolean sign,
                                              boolean encrypt,
                                              boolean radix64,
                                              boolean compress,
                                              int algorithm,
                                              ArrayList<EncryptionWrapper> data,
                                              String fileLocation,
                                              long signKeyID,
                                              String passphrase) throws PGPException, IOException, IllegalArgumentException {
        PGPPublicKey publicKey = null;
        PGPSecretKey secretKey = null;
        PGPPrivateKey privateKey = null;
        ArrayList<PGPPublicKey> publicKeys = new ArrayList<>();
        PGPSecretKeyRingCollection secretKeyRingCollection = null;
        if (sign) {
            secretKeyRingCollection = new PGPSecretKeyRingCollection(
                        PGPUtil.getDecoderStream(new FileInputStream(privateKeyFile)),
                        new JcaKeyFingerprintCalculator());
            privateKey = PGPutil.findPrivateKey(secretKeyRingCollection, signKeyID, passphrase);
            publicKey = secretKeyRingCollection.getSecretKey(signKeyID).getPublicKey();
            if(privateKey == null){
                throw new IllegalArgumentException("Private signature key not found.");
            }
            if(publicKey == null){
                throw new IllegalArgumentException("Public signature key not found.");
            }
            if (encrypt) {
                for (EncryptionWrapper pKey : data) {
                    secretKey = secretKeyRingCollection.getSecretKey(pKey.getKeyID());
                    if(secretKey == null){
                        throw new IllegalArgumentException("Key " + pKey.getUserName() + " not found.");
                    }
                    publicKeys.add(secretKey.getPublicKey());
                }
                PGPPublicKey[] publicKeysArray = new PGPPublicKey[publicKeys.size()];
                publicKeysArray = publicKeys.toArray(publicKeysArray);
                signAndEncrypt(fileLocation, privateKey, publicKey,
                        publicKeysArray, algorithm, radix64, compress);
            } else {
                signFile(fileLocation, privateKey, publicKey, radix64, compress);
            }
        } else if (encrypt) {
            secretKeyRingCollection = new PGPSecretKeyRingCollection(
                    PGPUtil.getDecoderStream(new FileInputStream(privateKeyFile)),
                    new JcaKeyFingerprintCalculator());
            for (EncryptionWrapper pKey : data) {
                secretKey = secretKeyRingCollection.getSecretKey(pKey.getKeyID());
                if (secretKey == null) {
                    throw new IllegalArgumentException("Public key " + pKey.getUserName() + " not found.");
                }
                publicKeys.add(secretKey.getPublicKey());
            }
            PGPPublicKey[] publicKeysArray = new PGPPublicKey[publicKeys.size()];
            publicKeysArray = publicKeys.toArray(publicKeysArray);
            encryptFile(fileLocation, publicKeysArray, algorithm, compress, radix64);
        }
    }

    /**
     *  Decrypt file with given name and verify its signatures
     *
     * @param inputFileName {@code String} for the file to be decrypted
     * @param passphrase {@code String} used to decode the {@link PGPSecretKey}
     * @param fileName {@code String} used to make a new decoded {@link File}
     *                       if file name not present use one from encoded data
     * @return {@code int[]}   <p>{@code ret[0] -1} <i>error</i>, {@code 0} <i>not present</i>, {@code 1}<i>verified</i>,
     *                          {@code 2} <i>failed</i> - <b>signature verification</b></p>
     *                           <p>{@code ret[1] -1} <i>error</i>, {@code 0} <i>not present</i>, {@code 1} <i>passed</i>,
     *                              {@code 2} <i>failed</i> - <b>integrity check</b></p>
     * @throws IOException
     * @throws PGPException
     * @throws SignatureException
     */
    public static int[] decryptionAndVerification(String inputFileName,
                                                     String passphrase,
                                                     String fileName) throws PGPException, IOException, SignatureException {
        return decryptAndVerify(inputFileName, privateKeyFile, publicKeyFile, passphrase, fileName);
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
     * @throws IOException
     * @throws PGPException
     */
    public static String encryptFile(String fileToEncrypt,
                            PGPPublicKey[] publicKeys,
                            int algorithm,
                            boolean compress,
                            boolean radix64) throws IOException, PGPException {
        logger.info("encryptFile(" + fileToEncrypt + ")");
        OutputStream outputStream;
        String encryptedFileName = fileToEncrypt;
        // Open new file to which data is written to
        if(radix64) {
            encryptedFileName += ".asc";
            outputStream = new ArmoredOutputStream(new FileOutputStream(encryptedFileName));
            logger.info("convert to radix64");
        } else {
            encryptedFileName += ".pgp";
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
        return encryptedFileName;
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
            publicKeyEncryptedData = (PGPPublicKeyEncryptedData)it.next();
            // until the private key found or reached the end of the stream
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

            String outputFileName = fileName;
            // If no file name given in input stream set default file name
            if (outputFileName.isBlank()) {
                outputFileName = literalData.getFileName();
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
     * Verify signature for the specified file
     *
     * @param fileToVerify name of the signed {@link File} to verify
     * @param publicKeyFileName {@code String} for the public key to be found
     * @return {@code boolean} true if file is verified, false otherwise
     * @throws IOException
     * @throws PGPException
     */
    private static boolean verifyFile(String fileToVerify,
                                     String publicKeyFileName,
                                      String fileName) throws IOException, PGPException, SignatureException {

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
        String outputFileName = fileName;
        // If no file name given set default file name
        if (fileName.isBlank()) {
            outputFileName = literalData.getFileName();
        }
        FileOutputStream fileOutputStream = new FileOutputStream(outputFileName);

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
    private static String signFile(
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
            fileName += ".pgp";
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

    /**
     * Sign file with provided private key and encrypt the file based on preferences
     *
     * @param fileToSign name of the signed {@link File} to sign
     * @param privateKey {@link PGPPrivateKey} used to sign the file
     * @param publicKey {@link PGPPublicKey} used to sign the file
     * @param publicKeys  array of {@link PGPPublicKey} which you wish to encrypt the data with
     * @param algorithm  algorithm to be used for encryption {@link SymmetricKeyAlgorithmTags}
     * @param radix64 if true encrypted data will be encoded with {@link ArmoredOutputStream}
     * @param compress  if true data will be compressed before encryption using
     *                      {@code ZIP} algorithm {@link CompressionAlgorithmTags}
     * @return {@code String} name of signed and encrypted {@link File}
     * @throws IOException
     * @throws PGPException
     */
    private static String signAndEncrypt(String fileToSign,
                                        PGPPrivateKey privateKey,
                                        PGPPublicKey publicKey,
                                        PGPPublicKey[] publicKeys,
                                        int algorithm,
                                        boolean radix64,
                                        boolean compress) throws IOException,PGPException {
        // literalOutput => compressedStrem => encryptedStream => outputStream
        logger.info("signFile(" + fileToSign + ")");
        OutputStream outputStream;
        String signedFile = fileToSign;
        if (radix64) {
            signedFile += ".asc";
            outputStream = new ArmoredOutputStream(new FileOutputStream(signedFile));
            logger.info("convert to radix64");
        } else {
            signedFile += ".pgp";
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

        PGPCompressedDataGenerator compressedDataGenerator = null;
        OutputStream compressedStream = null;
        PGPLiteralDataGenerator literalDataGenerator = new PGPLiteralDataGenerator();
        OutputStream literalOutputStream = null;
        File file = new File(fileToSign);
        byte[] fileBytes = new FileInputStream(file).readAllBytes();
        OutputStream encryptedStream = encryptedDataGenerator
                                            .open(outputStream, new byte[BUFFER_SIZE]);
        // Stream with which encrypted data is written to an output stream
        if(compress) {
            compressedDataGenerator = new PGPCompressedDataGenerator(ZIP_ALGORITHM);
            compressedStream =  compressedDataGenerator
                                .open(encryptedStream, new byte[BUFFER_SIZE]);
            signatureGenerator.generateOnePassVersion(true)
                    .encode(compressedStream);
            literalOutputStream = literalDataGenerator
                    .open(compressedStream, FILE_TYPE,
                            signedFile, new Date(file.lastModified()),
                            new byte[BUFFER_SIZE]);
//            PGPUtil.writeFileToLiteralData(compressedStream, FILE_TYPE, file, new byte[BUFFER_SIZE]);
            logger.info("file compressed");
        } else {
            signatureGenerator.generateOnePassVersion(true)
                    .encode(encryptedStream);
            literalOutputStream = literalDataGenerator
                    .open(encryptedStream, FILE_TYPE,
                            signedFile, new Date(file.lastModified()),
                            new byte[BUFFER_SIZE]);
//            PGPUtil.writeFileToLiteralData(encryptedStream, FILE_TYPE, file, new byte[BUFFER_SIZE]);
        }

        literalOutputStream.write(fileBytes, 0, fileBytes.length);
        signatureGenerator.update(fileBytes, 0, fileBytes.length);

        literalOutputStream.flush();
        literalOutputStream.close();
        literalDataGenerator.close();

        signatureGenerator.generate().encode(literalOutputStream);

        if(compress) {
//            compressedDataGenerator.close();
            compressedStream.flush();
            compressedStream.close();
        }

//        encryptedDataGenerator.close();

        encryptedStream.flush();
        encryptedStream.close();


        outputStream.flush();
        outputStream.close();
        logger.info("file " + fileToSign + " signed and encrypted");
        return signedFile;
    }

    /**
     *  Decrypt file with given name and verify its signatures
     *
     * @param inputFileName {@code String} for the file to be decrypted
     * @param secretKeyFileName {@code String} for the secret key to be found
     * @param publicKeyFileName {@code String} for the public key to be found
     * @param passphrase {@code String} used to decode the {@link PGPSecretKey}
     * @param fileName {@code String} used to make a new decoded {@link File}
     *                       if file name not present use one from encoded data
     * @return {@code int[]}   <p>{@code ret[0] -1} <i>error</i>, {@code 0} <i>not present</i>, {@code 1}<i>verified</i>,
     *                          {@code 2} <i>failed</i> - <b>signature verification</b></p>
 *                           <p>{@code ret[1] -1} <i>error</i>, {@code 0} <i>not present</i>, {@code 1} <i>passed</i>,
*                              {@code 2} <i>failed</i> - <b>integrity check</b></p>
     * @throws IOException
     * @throws PGPException
     * @throws SignatureException
     */
    private static int[] decryptAndVerify(String inputFileName,
                                           String secretKeyFileName,
                                           String publicKeyFileName,
                                           String passphrase,
                                           String fileName) throws IOException, PGPException {
        int[] ret = {-1, -1};
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
            try {
                privateKey = PGPutil.findPrivateKey(secretKeyRingCollection,
                        publicKeyEncryptedData.getKeyID(), passphrase);
            } catch (PGPException e){
                ret[0] = 3;
                fileInput.close();
                secretKeyInput.close();
                publicKeyInput.close();
                return ret;
            }
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
            } else if (object instanceof PGPOnePassSignatureList) {
                onePassSignatureList = (PGPOnePassSignatureList) object;
            } else if (object instanceof PGPSignatureList) {
                signatureList = (PGPSignatureList) object;
            } else {
                logger.info("Literal data input error.");
                throw new PGPException("message unknown message type.");
            }
            object = pgpObjects.nextObject();
        }

        if (onePassSignatureList == null && signatureList == null) {
            logger.info("signature verification not present.");
            ret[0] = 0;

            if (literalData != null) {
                String outputFileName = fileName;
                // If no file name given set default file name
                if (fileName.isBlank()) {
                    outputFileName = literalData.getFileName();
                }
                FileOutputStream fileOutputStream = new FileOutputStream(outputFileName);
                OutputStream BufferedFileOutputStream = new BufferedOutputStream(fileOutputStream);

                bytes = literalData.getInputStream().readAllBytes();
                BufferedFileOutputStream.write(bytes);
                BufferedFileOutputStream.flush();
                BufferedFileOutputStream.close();
            }

        } else if (onePassSignatureList != null && signatureList != null) {

            PGPOnePassSignature onePassSignature = onePassSignatureList.get(0);
            PGPPublicKeyRingCollection  publicKeyRingCollection = new PGPPublicKeyRingCollection(
                    PGPUtil.getDecoderStream(publicKeyInput), new JcaKeyFingerprintCalculator());

            PGPPublicKey publicKey = publicKeyRingCollection.getPublicKey(onePassSignature.getKeyID());

            if (publicKey != null && literalData != null) {
                onePassSignature.init(new JcaPGPContentVerifierBuilderProvider().setProvider("BC"), publicKey);
                String outputFileName = fileName;
                // If no file name given set default file name
                if (fileName.isBlank()) {
                    outputFileName = literalData.getFileName();
                }
                FileOutputStream fileOutputStream = new FileOutputStream(outputFileName);

                onePassSignature.init(new JcaPGPContentVerifierBuilderProvider()
                                .setProvider(PROVIDER),
                        publicKey);

                OutputStream BufferedFileOutputStream = new BufferedOutputStream(fileOutputStream);

                bytes = literalData.getInputStream().readAllBytes();

                onePassSignature.update(bytes);
                BufferedFileOutputStream.write(bytes);
                BufferedFileOutputStream.flush();
                BufferedFileOutputStream.close();
                if (onePassSignature.verify(signatureList.get(0))) {
                    logger.info("signature verified.");
                    ret[0] = 1;
                } else {
                    logger.info("signature verification failed.");
//                    throw new SignatureException("Signature verification failed");
                    ret[0] = 2;
                }
            }
        } else {
            logger.info("signature verification failed.");
//            throw new SignatureException("Signature verification failed");
            ret[0] = 2;
        }
        if (publicKeyEncryptedData.isIntegrityProtected()) {
            if (!publicKeyEncryptedData.verify()) {
                logger.info("message failed integrity check");
                ret[1] = 2;
            } else {
                logger.info("PGPPublicKeyEncryptedData passed integrity check");
                ret[1] = 1;
            }
        } else {
            logger.info("PGPPublicKeyEncryptedData no integrity check");
            ret[1] = 0;
        }
        fileInput.close();
        secretKeyInput.close();
        publicKeyInput.close();
        return ret;
    }

}