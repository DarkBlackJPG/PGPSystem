package utility;

/**
 * Sadrzi operacije koje se ticu kljuceva i obrade za keyring.
 * KeyManagement je singleton!
 * Sve klase u utility paketu bi trebalo da su singleton
 */
@Deprecated
public class KeyManagement {
//    private PGPSecretKeyRingCollection keyRingCollection;
//    private PGPKeyRingGenerator keyRingGenerator;
//
//    final private String secretKeyringPath = "secret.skr";
//    final private String publicKeyringPath = "public.pkr";
//    private User activeUser;
//    final private long secondsToExpire = 31622400 ;
//
//    private void initializeKeyRingCollection() throws IOException, PGPException {
//        keyRingCollection = null;
//        File keystoreFile = new File(secretKeyringPath);
//        if (keystoreFile.exists()) {
//            FileInputStream fileInputStream = new FileInputStream(keystoreFile);
//            keyRingCollection = new PGPSecretKeyRingCollection(fileInputStream, new JcaKeyFingerprintCalculator());
//        }
//    }
//
//    public KeyManagement() throws IOException, PGPException {
//        initializeKeyRingCollection();
//
//    }
//
//    public PGPSecretKeyRingCollection getKeyRingCollection() {
//        return keyRingCollection;
//    }
//    public PGPSecretKeyRing get() {
//        return keyRingGenerator.generateSecretKeyRing();
//    }
//
//
//    public void generateKeyring(RSA.KeySizes keySize) throws Exception {
//        activeUser = User.getUserInstance();
//        RSA rsaUtility = RSA.RSA_GetUtility();
//        rsaUtility.RSA_SetKeySize(keySize);
//        PGPKeyPair masterKeyPair = rsaUtility.RSA_PGPKeyGenerator();
//        PGPSignatureSubpacketGenerator signHashGen = new PGPSignatureSubpacketGenerator();
//        signHashGen.setKeyFlags(false, KeyFlags.SIGN_DATA | KeyFlags.CERTIFY_OTHER);
//        signHashGen.setPreferredSymmetricAlgorithms(false, new int[] {
//                SymmetricKeyAlgorithmTags.TRIPLE_DES,
//                SymmetricKeyAlgorithmTags.IDEA
//        });
//
//        signHashGen.setPreferredHashAlgorithms(false, new int[] {
//                HashAlgorithmTags.SHA1
//        });
//        signHashGen.setKeyExpirationTime(false, secondsToExpire);
//        PGPSignatureSubpacketGenerator encHashGen = new PGPSignatureSubpacketGenerator();
//        encHashGen.setKeyFlags(false, KeyFlags.ENCRYPT_COMMS | KeyFlags.ENCRYPT_STORAGE);
//
//
//        keyRingGenerator = new PGPKeyRingGenerator(
//                PGPSignature.DEFAULT_CERTIFICATION,
//                masterKeyPair,
//                String.format("%s <%s>",
//                        activeUser.getName(),
//                        activeUser.getEmail()),
//                new BcPGPDigestCalculatorProvider().get(HashAlgorithmTags.SHA1),
//                signHashGen.generate(),
//                encHashGen.generate(),
//                new BcPGPContentSignerBuilder(PGPPublicKey.RSA_SIGN, HashAlgorithmTags.SHA1),
//                new BcPBESecretKeyEncryptorBuilder(PGPEncryptedData.AES_256).build(activeUser.getPassword().toCharArray())
//        );
//
//        if (keyRingCollection != null) {
//            //
//            Iterator<PGPSecretKeyRing> pgpSecretKeyRingIterator =  keyRingCollection.getKeyRings(String.format("%s <%s>", activeUser.getName(), activeUser.getEmail()));
//            if (pgpSecretKeyRingIterator.hasNext()) {
//                keyRingGenerator = new PGPKeyRingGenerator(
//                        pgpSecretKeyRingIterator.next(),
//                        new BcPBESecretKeyDecryptorBuilder(new BcPGPDigestCalculatorProvider()).build(activeUser.getPassword().toCharArray()),
//                        new BcPGPDigestCalculatorProvider().get(HashAlgorithmTags.SHA1),
//                        new BcPGPContentSignerBuilder(PGPPublicKey.RSA_SIGN, HashAlgorithmTags.SHA1),
//                        new BcPBESecretKeyEncryptorBuilder(PGPEncryptedData.AES_256).build(activeUser.getPassword().toCharArray())
//                );
//            } else {
//                ArrayList<PGPSecretKeyRing> keyRings = new ArrayList<>();
//                pgpSecretKeyRingIterator.forEachRemaining(keyRings::add);
//                keyRingCollection = new PGPSecretKeyRingCollection(keyRings);
//            }
//        } else {
//            ArrayList<PGPSecretKeyRing> keyRings = new ArrayList<>();
//            keyRings.add(keyRingGenerator.generateSecretKeyRing());
//            keyRingCollection = new PGPSecretKeyRingCollection(keyRings);
//        }
//    }
//
//    public PGPPublicKey getAsymmetricEncryptionKey() {
//        if (keyRingGenerator != null) {
//         return keyRingGenerator.generatePublicKeyRing().getPublicKey();
//        }
//        return null;
//    }
//
//    public PGPSecretKey getAsymmetricSigningKey() {
//        if (keyRingGenerator != null) {
//            return keyRingGenerator.generateSecretKeyRing().getSecretKey();
//        }
//        return null;
//    }
//
//    public static void exportPublicKey(PGPPublicKey pgpPublicKey, String exportedPublicKeyPath) throws IOException {
//        writeKeyToFile(exportedPublicKeyPath, pgpPublicKey.getEncoded());
//    }
//    public static void exportSecretKey(PGPSecretKey pgpSecretKey, String exportedSecretKeyPath) throws IOException {
//        writeKeyToFile(exportedSecretKeyPath, pgpSecretKey.getEncoded());
//    }
//
//    private static void writeKeyToFile(String exportedPublicKeyPath, byte[] encoded) throws IOException {
//        File extractedKey = new File(exportedPublicKeyPath);
//        extractedKey.createNewFile();
//        FileOutputStream os = new FileOutputStream(extractedKey);
//        ArmoredOutputStream armorOut = new ArmoredOutputStream(os);
//        armorOut.write(encoded);
//        armorOut.flush();
//        armorOut.close();
//        os.close();
//    }
//
//    private void writeToFile(String filename, PGPKeyRing keyRing) throws IOException {
//        File secretKeyringFile = new File(filename);
//        secretKeyringFile.createNewFile();
//        FileOutputStream secretOut = new FileOutputStream(secretKeyringFile);
//        keyRing.encode(secretOut);
//        secretOut.close();
//    }
//    public void saveKeyrings() throws IOException {
//        writeToFile(secretKeyringPath, keyRingGenerator.generateSecretKeyRing());
//        writeToFile(publicKeyringPath, keyRingGenerator.generatePublicKeyRing());
//    }
}
