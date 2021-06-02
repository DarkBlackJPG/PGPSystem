package utility.helper;

import utility.KeyManager.ExportedKeyData;

import java.util.EnumSet;

public class DecryptionVerificationWrapper {
    private ExportedKeyData exportedKeyData;
    private DecryptionCode decryptionCode;
    private VerificationCode verificationCode;
    private String outputFilePath;

    public enum DecryptionCode {
        ERROR, NO_INTEGRITY_CHECK, NOT_ENCRYPTED, PASSED, FAILED,
        NO_PUBLIC_KEY;

        public static boolean containsWarnings(DecryptionCode o){
            return DecryptionCode.getWarnings().contains(o);
        }

        public static boolean containsErrors(DecryptionCode o){
            return DecryptionCode.getErrors().contains(o);
        }

        private static EnumSet<DecryptionCode> getWarnings() {
            return EnumSet.of(NOT_ENCRYPTED, NO_INTEGRITY_CHECK);
        }

        private static EnumSet<DecryptionCode> getErrors() {
            return EnumSet.of(ERROR, FAILED, NO_PUBLIC_KEY);
        }
    }

    public enum VerificationCode {
        ERROR, NOT_PRESENT, VERIFIED, FAILED,
        WRONG_PASSPHRASE, NO_PRIVATE_KEY, INVALID;

        public static boolean containsWarnings(VerificationCode o){
            return VerificationCode.getWarnings().contains(o);
        }

        public static boolean containsErrors(VerificationCode o){
            return VerificationCode.getErrors().contains(o);
        }

        private static EnumSet<VerificationCode> getWarnings() {
            return EnumSet.of(NOT_PRESENT);
        }

        private static EnumSet<VerificationCode> getErrors() {
            return EnumSet.of(ERROR, FAILED, NO_PRIVATE_KEY, INVALID);
        }
    }

    public DecryptionVerificationWrapper(ExportedKeyData exportedKeyData,
                                         DecryptionCode decryptionCode,
                                         VerificationCode verificationCode,
                                         String outputFilePath) {
        this.exportedKeyData = exportedKeyData;
        this.decryptionCode = decryptionCode;
        this.verificationCode = verificationCode;
        this.outputFilePath = outputFilePath;
    }

    public ExportedKeyData getExportedKeyData() {
        return exportedKeyData;
    }

    public void setExportedKeyData(ExportedKeyData exportedKeyData) {
        this.exportedKeyData = exportedKeyData;
    }

    public DecryptionCode getDecryptionCode() {
        return decryptionCode;
    }

    public void setDecryptionCode(DecryptionCode decryptionCode) {
        this.decryptionCode = decryptionCode;
    }

    public VerificationCode getVerificationCode() {
        return verificationCode;
    }

    public void setVerificationCode(VerificationCode verificationCode) {
        this.verificationCode = verificationCode;
    }
}
