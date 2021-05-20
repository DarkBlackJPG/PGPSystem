package utility.KeyManager;

import ExceptionPackage.KeyNotFoundException;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import utility.ExportedKeyData;

import java.io.*;
import java.security.Key;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.time.temporal.ChronoUnit;
import java.time.temporal.TemporalUnit;
import java.util.ArrayList;
import java.util.Date;
import java.util.Iterator;

public class KeyringManager implements Keyring{
    private PGPSecretKeyRingCollection secretKeyRings;
    private PGPPublicKeyRingCollection publicKeyRings;

    @Override
    public void importSecretKeyring(InputStream is) throws IOException, PGPException {
        secretKeyRings = new PGPSecretKeyRingCollection(is, new JcaKeyFingerprintCalculator());
    }

    @Override
    public void importPublicKeyring(InputStream is) throws IOException, PGPException {
        publicKeyRings = new PGPPublicKeyRingCollection(is, new JcaKeyFingerprintCalculator());
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
    public void addSecretKey(InputStream secretKey) {

    }

    @Override
    public void addPublicKey(InputStream publicKey) {

    }

    @Override
    public ArrayList<ExportedKeyData> generatePublicKeyList() {
        return generatePublicKeyList(publicKeyRings, secretKeyRings);
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
        LocalDate temp =  pgp.getCreationTime()
                .toInstant()
                .atZone(ZoneId.systemDefault()).toLocalDate()
                .plus(pgp.getValidSeconds(), ChronoUnit.SECONDS);
        Date tempDate = Date.from(temp.atStartOfDay().toInstant(ZoneOffset.MIN));
        keyData.setValidUntil(tempDate);
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
            data.add(extractDataFromKey(pgpSecretKeys));
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
    public void saveKeys(PGPPublicKeyRingCollection publicKeyRingCollection, PGPSecretKeyRingCollection secretKeyRingCollection, String publicKeyFileLocation, String secretKeyFileLocation) throws IOException {
        // TODO validacija putanje
        File publicFile = new File(publicKeyFileLocation + "publicKeys_" + LocalDate.now() + ".pkr");
        File secretFile = new File(secretKeyFileLocation + "secretKeys_" + LocalDate.now() + ".skr");
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
