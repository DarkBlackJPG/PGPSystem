package utility.KeyManager;

import ExceptionPackage.IncorrectKeyException;
import ExceptionPackage.KeyNotFoundException;
import org.apache.tools.ant.DirectoryScanner;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.bcpg.sig.KeyFlags;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyEncryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;

import java.io.*;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.Iterator;

public class KeyringManager implements Keyring {
    private PGPSecretKeyRingCollection secretKeyRings;
    private PGPPublicKeyRingCollection publicKeyRings;

    // Podrazumevano godinu dana
    final private long secondsToExpire = 31622400;
    public final static String privateKeyFile = "system_secretKeys.skr";
    public final static String publicKeyFile = "system_publicKeys.pkr";
    /**
     * Ovo koristim da pretrazimo fajlsistem za trazeni fajl i da vratimo
     * putanju od korenog dir.
     * Na primer ako je root ./
     * U root imamo fajl asdf.txt i folder a i unutar njega a/fdsa.txt
     * ako trazimo asdf.txt on vrasca "asdf.txt"
     * <p>
     * Ako trazimo fdsa.txt, vraca a/fdsa.txt
     *
     * @param filename
     * @return
     */
    private String scanForFile(String filename) {
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
        this.secretKeyRings = new PGPSecretKeyRingCollection(new ArrayList<>());
        this.publicKeyRings = new PGPPublicKeyRingCollection(new ArrayList<>());

        try {
            String secretKeyFile = scanForFile("system_secretKeys.skr");
            String publicKeyFile = scanForFile("system_publicKeys.pkr");

            // Ne znam ovo da ekstrahujem u metodu

            if (secretKeyFile != null) {
                File secretKeyring = new File(secretKeyFile);
                InputStream fis = new FileInputStream(secretKeyring);
                fis = PGPUtil.getDecoderStream(fis);
                secretKeyRings = new PGPSecretKeyRingCollection(fis, new BcKeyFingerprintCalculator());
            }

            if (publicKeyFile != null) {
                File publicKeyring = new File(publicKeyFile);
                InputStream fis = new FileInputStream(publicKeyring);
                fis = PGPUtil.getDecoderStream(fis);
                publicKeyRings = new PGPPublicKeyRingCollection(fis, new BcKeyFingerprintCalculator());
            }

        } catch (Exception e) {
            System.err.println("Keyring object encountered a fatal error!");
        }
    }

    @Override
    public ExportedKeyData importSecretKeyring(InputStream inputStream) throws IOException, PGPException {
        inputStream = PGPUtil.getDecoderStream(inputStream);
        PGPSecretKeyRingCollection pgpSec = new PGPSecretKeyRingCollection(inputStream, new BcKeyFingerprintCalculator());
        Iterator<PGPSecretKeyRing> keyRings = pgpSec.getKeyRings();
        PGPSecretKeyRing newSecretKey = keyRings.next();
        addSecretKey(newSecretKey);
        ArrayList<PGPPublicKey> publicKeys = new ArrayList<>();
        publicKeys.add(newSecretKey.getPublicKey());
        PGPPublicKeyRing pgpPublicKeyRing = new PGPPublicKeyRing(publicKeys);
        addPublicKey(pgpPublicKeyRing);
        ExportedKeyData keyData = extractDataFromKey(pgpPublicKeyRing);
        keyData.setMasterKey(true);
        return keyData;
    }

    @Override
    public ExportedKeyData makeKeyPairs(PGPKeyPair masterKey, PGPKeyPair subKey, String username, String email, String password) throws PGPException, IOException {

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
                masterKey,
                String.format("%s <%s>",
                        username,
                        email),
                new BcPGPDigestCalculatorProvider().get(HashAlgorithmTags.SHA1),
                signHashGen.generate(),
                null,
                new BcPGPContentSignerBuilder(PGPPublicKey.RSA_SIGN, HashAlgorithmTags.SHA1),
                new BcPBESecretKeyEncryptorBuilder(PGPEncryptedData.AES_256).build(password.toCharArray())
        );
        keyRingGenerator.addSubKey(subKey, encHashGen.generate(), null);
        PGPSecretKeyRing secretKeys = keyRingGenerator.generateSecretKeyRing();
        PGPPublicKeyRing pgpPublicKeys = keyRingGenerator.generatePublicKeyRing();
        addSecretKey(secretKeys);
        addPublicKey(pgpPublicKeys);

        // Cuva na root
        saveKeys("system_publicKeys.pkr", "system_secretKeys.skr");

        ExportedKeyData data = extractDataFromKey(secretKeys);
        data.setMasterKey(true);
        return data;

    }

    /**
     * @param inputStream
     * @throws IOException
     * @throws PGPException
     * @see <a href="https://stackoverflow.com/questions/28444819/getting-bouncycastle-to-decrypt-a-gpg-encrypted-message">
     * Odavde je preuzet kod za dekriptovanje
     * </a>
     * @return
     */
    @Override
    public ExportedKeyData importPublicKeyring(InputStream inputStream) throws IOException, PGPException {
        inputStream = PGPUtil.getDecoderStream(inputStream);
        PGPPublicKeyRingCollection pgpSec = new PGPPublicKeyRingCollection(inputStream, new BcKeyFingerprintCalculator());
        Iterator<PGPPublicKeyRing> keyRings = pgpSec.getKeyRings();
        PGPPublicKeyRing newPublicKey = keyRings.next();
        addPublicKey(newPublicKey);
        return extractDataFromKey(newPublicKey);
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

    // TODO: Sta ako nema kljuca???
    @Override
    public void exportPublicKey(PGPPublicKeyRing pgpPublicKey, OutputStream os) throws PGPException, IOException {
        writeKeyToFile(os, pgpPublicKey.getEncoded());
    }

    @Override
    public void exportPublicKey(long KeyId, OutputStream os) throws PGPException, IOException {
        if (publicKeyRings.contains(KeyId)) {
            exportPublicKey(publicKeyRings.getPublicKeyRing(KeyId), os);
        }
    }

    @Override
    public void removeSecretKey(long KeyId, String password) throws PGPException, IncorrectKeyException {
        PGPSecretKeyRing pgpSecretKeyRing = secretKeyRings.getSecretKeyRing(KeyId);
        removeSecretKey(pgpSecretKeyRing, password);
    }

    // TODO: Sta ako key ne postoji sa ovim ID?
    @Override
    public void removeSecretKey(PGPSecretKeyRing keyRing, String password) throws IncorrectKeyException {
        // TODO: Implementirati
        PGPSecretKey pgpSecretKey = keyRing.getSecretKey();
        try {
            PGPPrivateKey privateKey = pgpSecretKey.extractPrivateKey(new JcePBESecretKeyDecryptorBuilder().setProvider("BC").build(password.toCharArray()));
            removeGivenSecretKeyFromCollection(keyRing);
        } catch (Exception exp) {
            throw new IncorrectKeyException();
        }
    }

    /**
     * Uzimamo sve kljuceve iz kolekcije, pravimo listu tako sto dodajemo
     * ako nije keyring koji brisemo
     *
     * @param keyRing
     * @throws IOException
     * @throws PGPException
     */
    private void removeGivenSecretKeyFromCollection(PGPSecretKeyRing keyRing) throws IOException, PGPException {
        Iterator<PGPSecretKeyRing> keys = secretKeyRings.getKeyRings();
        ArrayList<PGPSecretKeyRing> newArray = new ArrayList<>();
        keys.forEachRemaining(keyRing1 -> {
            if (keyRing1.getSecretKey().getKeyID() != keyRing.getSecretKey().getKeyID()) {
                newArray.add(keyRing1);
            }
        });
        secretKeyRings = new PGPSecretKeyRingCollection(newArray);
    }

    /**
     * Isto kao i za private brisanje
     *
     * @param keyRing
     * @throws IOException
     * @throws PGPException
     */
    private void removeGivenPublicKeyFromCollection(PGPPublicKeyRing keyRing) throws IOException, PGPException {
        Iterator<PGPPublicKeyRing> keys = publicKeyRings.getKeyRings();
        ArrayList<PGPPublicKeyRing> newArray = new ArrayList<>();
        keys.forEachRemaining(keyRing1 -> {
            if (keyRing1.getPublicKey().getKeyID() != keyRing.getPublicKey().getKeyID()) {
                newArray.add(keyRing1);
            }
        });
        publicKeyRings = new PGPPublicKeyRingCollection(newArray);
    }

    // TODO: Sta ako key ne postoji sa ovim ID?
    @Override
    public void removePublicKey(long KeyId) throws PGPException, IOException {
        PGPPublicKeyRing pgpPublicKeys = publicKeyRings.getPublicKeyRing(KeyId);
        removePublicKey(pgpPublicKeys);
    }

    @Override
    public void removePublicKey(PGPPublicKeyRing keyRing) throws IOException, PGPException {
        removeGivenPublicKeyFromCollection(keyRing);
    }

    @Override
    public ArrayList<ExportedKeyData> generatePublicKeyList() {
        return generatePublicKeyList(publicKeyRings, secretKeyRings);
    }

    /**
     * Ovo koristimo da nadovezemo sekunde vazenja
     * na datum pravljenja kljuca, pogledaj javinu dok za ovo
     *
     * @param date
     * @param seconds
     * @return
     */
    private static Date addSeconds(Date date, Long seconds) {
        Calendar cal = Calendar.getInstance();
        cal.setTime(date);
        cal.add(Calendar.SECOND, Math.toIntExact(seconds));
        return cal.getTime();
    }

    /**
     * 1. Napravi novi obj ExportedKeyData
     * 2. Dohvati javni kljuc (radi za priv i javni jer prosledjujemo keyRING)
     * 3. Ekstrahuj user ID (Oblik je Username <email>)
     * 4. Delimo username i email iz user ID
     * 5. Punimo podatke exported data key
     * <p>
     * Vazna napomena, podrazumevano je master Key false,
     * ako se ocekuje master key, treba nekako da se zameni!
     *
     * @param pgpRing
     * @return
     */
    public static ExportedKeyData extractDataFromKey(PGPKeyRing pgpRing) {
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


    /**
     * ArmoredOutputStream koristim za sve keyexporte - meni lakse, svima lakse
     * Armored output samo znaci Base64 konverzija.
     *
     * @param outputStream
     * @param encoded
     * @throws IOException
     */
    private static void writeKeyToFile(OutputStream outputStream, byte[] encoded) throws IOException {
        ArmoredOutputStream armorOut = new ArmoredOutputStream(outputStream);
        armorOut.write(encoded);
        armorOut.flush();
        armorOut.close();
        outputStream.close();
    }

    @Override
    public void saveKeys() throws IOException {
        saveKeys(publicKeyRings, secretKeyRings, publicKeyFile, privateKeyFile);
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
    public void exportSecretKey(long KeyID, OutputStream outputStream) throws PGPException, IOException, KeyNotFoundException {
        if (secretKeyRings.contains(KeyID)) {
            exportSecretKey(secretKeyRings.getSecretKeyRing(KeyID), outputStream);
        } else {
            throw new KeyNotFoundException();
        }
    }

    @Override
    public void exportSecretKey(PGPSecretKeyRing key, OutputStream outputStream) throws IOException {
        writeKeyToFile(outputStream, key.getEncoded());
    }


    @Override
    public PGPSecretKey getSecretKeyById(long keyId) throws PGPException {
        return secretKeyRings.getSecretKey(keyId);
    }


    @Override
    public PGPPrivateKey decryptSecretKey(PGPSecretKey secretKey, String password) {
        try {
            return secretKey.extractPrivateKey(new JcePBESecretKeyDecryptorBuilder().setProvider("BC").build(password.toCharArray()));
        } catch (Exception exp) {
            return null;
        }
    }


    @Override
    public boolean checkPasswordMatch(PGPSecretKey secretKey, String password) {
        try {
            secretKey.extractPrivateKey(new JcePBESecretKeyDecryptorBuilder().setProvider("BC").build(password.toCharArray()));
            return true;
        } catch (Exception exp) {
            return false;
        }
    }
}