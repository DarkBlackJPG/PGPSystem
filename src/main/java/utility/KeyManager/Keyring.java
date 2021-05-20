package utility.KeyManager;

import ExceptionPackage.KeyNotFoundException;
import org.bouncycastle.openpgp.*;
import utility.ExportedKeyData;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;

public interface Keyring {
    void importSecretKeyring(InputStream is) throws IOException, PGPException;
    void importPublicKeyring(InputStream is) throws IOException, PGPException;

    void addSecretKey(PGPSecretKeyRing secretKey) throws IOException, PGPException;
    void addPublicKey(PGPPublicKeyRing publicKey) throws IOException, PGPException;

    void addSecretKey(InputStream secretKey);
    void addPublicKey(InputStream publicKey);

    void saveKeys(String publicKeyFileLocation, String secretKeyFileLocation) throws IOException;
    void saveKeys(PGPPublicKeyRingCollection publicKeyRings, PGPSecretKeyRingCollection secretKeyRings, String publicKeyFileLocation, String secretKeyFileLocation) throws IOException;

    void exportKeyPair(long KeyID, OutputStream outputStream) throws PGPException, IOException, KeyNotFoundException;
    void exportKeyPair(PGPSecretKey key, OutputStream outputStream) throws IOException;

    ArrayList<ExportedKeyData> generatePublicKeyList();
    ArrayList<ExportedKeyData> generatePublicKeyList(PGPPublicKeyRingCollection publicKeyRings, PGPSecretKeyRingCollection secretKeyRings);
}
