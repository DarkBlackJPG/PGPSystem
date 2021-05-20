package utility.KeyManager;

import ExceptionPackage.KeyNotFoundException;
import org.apache.log4j.Logger;
import org.apache.tools.ant.DirectoryScanner;
import org.bouncycastle.bcpg.*;
import org.bouncycastle.bcpg.sig.KeyFlags;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.jcajce.provider.symmetric.util.BaseSecretKeyFactory;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.bc.*;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;
import utility.ExportedKeyData;
import utility.RSA;
import utility.User;

import javax.crypto.SecretKeyFactory;
import java.io.*;
import java.security.Key;
import java.security.PublicKey;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.time.temporal.ChronoUnit;
import java.time.temporal.TemporalUnit;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.Iterator;

public class KeyringManager implements Keyring {
    private PGPSecretKeyRingCollection secretKeyRings;
    private PGPPublicKeyRingCollection publicKeyRings;
    final private long secondsToExpire = 31622400;

    final static Logger logger = Logger.getLogger(KeyringManager.class);

    public String scanForFile(String filename) {
        DirectoryScanner scanner = new DirectoryScanner();
        scanner.setIncludes(new String[]{"**/" + filename});
        scanner.setBasedir(new File("").getAbsolutePath());
        scanner.setCaseSensitive(false);
        scanner.scan();
        if (scanner.getIncludedFilesCount() > 0) {
            return scanner.getIncludedFiles()[0];
        } else {
            return null;
        }
    }

    public KeyringManager() throws IOException, PGPException {
        logger.info("Keymanager created");
        this.secretKeyRings = new PGPSecretKeyRingCollection(new ArrayList<>());
        this.publicKeyRings = new PGPPublicKeyRingCollection(new ArrayList<>());

        try {
            String secretKeyFile = scanForFile("system_secretKeys.skr");
            String publicKeyFile = scanForFile("system_publicKeys.skr");

            // Ne znam ovo da ekstrahujem u metodu

            if (secretKeyFile != null) {
                File secretKeyring = new File(secretKeyFile);
                FileInputStream fis = new FileInputStream(secretKeyring);
                secretKeyRings = new PGPSecretKeyRingCollection(fis, new JcaKeyFingerprintCalculator());
            }

            if (publicKeyFile != null) {
                File publicKeyring = new File(publicKeyFile);
                FileInputStream fis = new FileInputStream(publicKeyring);
                publicKeyRings = new PGPPublicKeyRingCollection(fis, new JcaKeyFingerprintCalculator());
            }

        } catch (Exception e) {
            logger.error("Keyring object encountered a fatal error!");
        }
    }

    @Override
    public void importSecretKeyring(InputStream is) throws IOException, PGPException {
        secretKeyRings = new PGPSecretKeyRingCollection(is, new JcaKeyFingerprintCalculator());
    }

    @Override
    public PGPPublicKeyRing makeKeyPairsTEST(PGPKeyPair pgpKeyPair, String username, String email, String password) throws PGPException, IOException {
        PGPSignatureSubpacketGenerator signHashGen = new PGPSignatureSubpacketGenerator();
        signHashGen.setKeyFlags(false, KeyFlags.SIGN_DATA | KeyFlags.CERTIFY_OTHER | KeyFlags.ENCRYPT_STORAGE | KeyFlags.ENCRYPT_COMMS);
        signHashGen.setPreferredSymmetricAlgorithms(false, new int[]{
                SymmetricKeyAlgorithmTags.TRIPLE_DES,
                SymmetricKeyAlgorithmTags.IDEA
        });
        signHashGen.setPreferredHashAlgorithms(false, new int[]{
                HashAlgorithmTags.SHA1
        });
        signHashGen.setKeyExpirationTime(false, secondsToExpire);
        signHashGen.setPreferredCompressionAlgorithms(false, new int[]{CompressionAlgorithmTags.ZIP});

        PGPSignatureSubpacketGenerator encHashGen = new PGPSignatureSubpacketGenerator();
        encHashGen.setKeyFlags(false, KeyFlags.ENCRYPT_COMMS | KeyFlags.ENCRYPT_STORAGE);

        PGPKeyRingGenerator keyRingGenerator = new PGPKeyRingGenerator(
                PGPSignature.DEFAULT_CERTIFICATION,
                pgpKeyPair,
                String.format("%s <%s>",
                        username,
                        email),
                new BcPGPDigestCalculatorProvider().get(HashAlgorithmTags.SHA1),
                signHashGen.generate(),
                encHashGen.generate(),
                new BcPGPContentSignerBuilder(PGPPublicKey.RSA_SIGN, HashAlgorithmTags.SHA1),
                new BcPBESecretKeyEncryptorBuilder(PGPEncryptedData.AES_256).build(password.toCharArray())
        );

        PGPSecretKeyRing secretKeys = keyRingGenerator.generateSecretKeyRing();
        PGPPublicKeyRing pgpPublicKeys = keyRingGenerator.generatePublicKeyRing();

        return pgpPublicKeys;
    }

    @Override
    public void makeKeyPairs(PGPKeyPair pgpKeyPair, String username, String email, String password) throws PGPException, IOException {

        PGPSignatureSubpacketGenerator signHashGen = new PGPSignatureSubpacketGenerator();
        signHashGen.setKeyFlags(false, KeyFlags.SIGN_DATA | KeyFlags.CERTIFY_OTHER);
        signHashGen.setPreferredSymmetricAlgorithms(false, new int[]{
                SymmetricKeyAlgorithmTags.TRIPLE_DES,
                SymmetricKeyAlgorithmTags.IDEA
        });
        signHashGen.setPreferredHashAlgorithms(false, new int[]{
                HashAlgorithmTags.SHA1
        });
        signHashGen.setKeyExpirationTime(false, secondsToExpire);


        PGPSignatureSubpacketGenerator encHashGen = new PGPSignatureSubpacketGenerator();
        encHashGen.setKeyFlags(false, KeyFlags.ENCRYPT_COMMS | KeyFlags.ENCRYPT_STORAGE);

        PGPKeyRingGenerator keyRingGenerator = new PGPKeyRingGenerator(
                PGPSignature.DEFAULT_CERTIFICATION,
                pgpKeyPair,
                String.format("%s <%s>",
                        username,
                        email),
                new BcPGPDigestCalculatorProvider().get(HashAlgorithmTags.SHA1),
                signHashGen.generate(),
                encHashGen.generate(),
                new BcPGPContentSignerBuilder(PGPPublicKey.RSA_SIGN, HashAlgorithmTags.SHA1),
                new BcPBESecretKeyEncryptorBuilder(PGPEncryptedData.AES_256).build(password.toCharArray())
        );

        PGPSecretKeyRing secretKeys = keyRingGenerator.generateSecretKeyRing();
        PGPPublicKeyRing pgpPublicKeys = keyRingGenerator.generatePublicKeyRing();

        addPublicKey(pgpPublicKeys);
        addSecretKey(secretKeys);

        // Cuva na root
        saveKeys("system_publicKeys.pkr", "system_secretKeys.skr");
    }

    /**
     *
     *
     * @param is
     * @throws IOException
     * @throws PGPException
     */
    @Override
    public void importPublicKeyring(InputStream is) throws IOException, PGPException {
        is = PGPUtil.getDecoderStream(is);
        PGPPublicKeyRingCollection pgpSec = new PGPPublicKeyRingCollection(is, new BcKeyFingerprintCalculator());
        Iterator<PGPPublicKeyRing> keyRings = pgpSec.getKeyRings();
        PGPPublicKeyRing newPublicKey = keyRings.next();
        addPublicKey(newPublicKey);
    }

    @Override
    public void addSecretKey(PGPSecretKeyRing secretKey) throws IOException, PGPException {
        ArrayList<PGPSecretKeyRing> secretKeys = new ArrayList<>();
        secretKeyRings.getKeyRings().forEachRemaining(secretKeys::add);
        secretKeys.add(secretKey);
        secretKeyRings = new PGPSecretKeyRingCollection(secretKeys);
    }

    @Override
    public void addPublicKey(PGPPublicKeyRing publicKey) throws IOException, PGPException {
        ArrayList<PGPPublicKeyRing> publicKeys = new ArrayList<>();
        publicKeyRings.getKeyRings().forEachRemaining(publicKeys::add);
        publicKeys.add(publicKey);
        publicKeyRings = new PGPPublicKeyRingCollection(publicKeys);
    }

    @Override
    public void importKeyPair(InputStream inputStream) throws IOException {
        ArmoredInputStream armoredInputStream = new ArmoredInputStream(inputStream);

    }

    @Override
    public void addSecretKey(InputStream secretKey) throws IOException, PGPException {
        secretKey = PGPUtil.getDecoderStream(secretKey);
        PGPSecretKeyRingCollection pgpSec = new PGPSecretKeyRingCollection(secretKey, new BcKeyFingerprintCalculator());

        System.out.println();

    }

    @Override
    public void addPublicKey(InputStream publicKey) throws IOException, PGPException {
        PGPPublicKeyRing keyRing = new PGPPublicKeyRing(publicKey, new JcaKeyFingerprintCalculator());
        addPublicKey(keyRing);
    }

    @Override
    public void exportPublicKey(long KeyId, OutputStream os) throws PGPException, IOException {
        PGPSecretKey secretKey = secretKeyRings.getSecretKey(KeyId);
        if (secretKey != null && secretKey.getKeyID() == KeyId) {
            writeKeyToFile(os, secretKey.getPublicKey().getEncoded());
        }

    }

    @Override
    public ArrayList<ExportedKeyData> generatePublicKeyList() {
        return generatePublicKeyList(publicKeyRings, secretKeyRings);
    }

    private static Date addSeconds(Date date, Long seconds) {
        Calendar cal = Calendar.getInstance();
        cal.setTime(date);
        cal.add(Calendar.SECOND, Math.toIntExact(seconds));
        return cal.getTime();
    }

    private ExportedKeyData extractDataFromKey(PGPKeyRing pgpRing) {
        ExportedKeyData keyData = new ExportedKeyData();
        PGPPublicKey pgp = pgpRing.getPublicKey();
        String userID = pgp.getUserIDs().next();
        String[] split = userID.split("<");
        keyData.setUserName(split[0].trim());
        if (split.length > 1) {
            keyData.setEmail(split[1].replace(">", ""));
        } else {
            keyData.setEmail("");
        }
        keyData.setKeyID(pgp.getKeyID());
        keyData.setMasterKey(false);
        keyData.setValidFrom(pgp.getCreationTime());

        keyData.setValidUntil(addSeconds(pgp.getCreationTime(), pgp.getValidSeconds()));
        return keyData;
    }

    @Override
    public ArrayList<ExportedKeyData> generatePublicKeyList(PGPPublicKeyRingCollection publicKeyRings, PGPSecretKeyRingCollection secretKeyRings) {
        Iterator<PGPPublicKeyRing> publicKeys = publicKeyRings.getKeyRings();
        Iterator<PGPSecretKeyRing> secretKeys = secretKeyRings.getKeyRings();
        ArrayList<ExportedKeyData> data = new ArrayList<>();

        publicKeys.forEachRemaining(pgpPublicKeys -> {
            data.add(extractDataFromKey(pgpPublicKeys));
        });
        secretKeys.forEachRemaining(pgpSecretKeys -> {
            data.forEach(exportedKeyData -> {
                if (exportedKeyData.getKeyID() == pgpSecretKeys.getSecretKey().getKeyID()) {
                    exportedKeyData.setMasterKey(true);
                }
            });
        });

        return data;
    }


    private static void writeKeyToFile(OutputStream outputStream, byte[] encoded) throws IOException {
        ArmoredOutputStream armorOut = new ArmoredOutputStream(outputStream);
        armorOut.write(encoded);
        armorOut.flush();
        armorOut.close();
        outputStream.close();
    }

    @Override
    public void saveKeys(String publicKeyFileLocation, String secretKeyFileLocation) throws IOException {
        saveKeys(publicKeyRings, secretKeyRings, publicKeyFileLocation, secretKeyFileLocation);
    }

    @Override
    public void saveKeys(PGPPublicKeyRingCollection publicKeyRingCollection,
                         PGPSecretKeyRingCollection secretKeyRingCollection,
                         String publicKeyFileLocation,
                         String secretKeyFileLocation) throws IOException {
        // TODO validacija putanje
        File publicFile = new File(publicKeyFileLocation);
        File secretFile = new File(secretKeyFileLocation);
        FileOutputStream publicFos = new FileOutputStream(publicFile);
        FileOutputStream secretFos = new FileOutputStream(secretFile);
        writeKeyToFile(publicFos, publicKeyRingCollection.getEncoded());
        writeKeyToFile(secretFos, secretKeyRingCollection.getEncoded());
    }

    @Override
    public void exportKeyPair(long KeyID, OutputStream outputStream) throws PGPException, IOException, KeyNotFoundException {
        if (secretKeyRings.contains(KeyID)) {
            PGPSecretKey pgpSecretKey = secretKeyRings.getSecretKey(KeyID);
            exportKeyPair(pgpSecretKey, outputStream);
        } else {
            throw new KeyNotFoundException();
        }
    }

    @Override
    public void exportKeyPair(PGPSecretKey key, OutputStream outputStream) throws IOException {
        writeKeyToFile(outputStream, key.getEncoded());
    }
}
