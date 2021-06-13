package etf.openpgp.ts170124dss170372d.utility.helper;


import etf.openpgp.ts170124dss170372d.utility.KeyManager.ExportedKeyData;

import java.util.Date;
import java.util.EnumSet;

/**
 * Class for the return data of file verification and decryption
 */
public class DecryptionVerificationWrapper {
    private ExportedKeyData exportedKeyData;
    private DecryptionCode decryptionCode;
    private VerificationCode verificationCode;
    private String outputFilePath;
    private Date timeOfCreation;

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

    public String getOutputFilePath() {
        return outputFilePath;
    }

    public void setOutputFilePath(String outputFilePath) {
        this.outputFilePath = outputFilePath;
    }

    public Date getTimeOfCreation() {
        return timeOfCreation;
    }

    public void setTimeOfCreation(Date timeOfCreation) {
        this.timeOfCreation = timeOfCreation;
    }

    public DecryptionVerificationWrapper(ExportedKeyData exportedKeyData,
                                         DecryptionCode decryptionCode,
                                         VerificationCode verificationCode,
                                         String outputFilePath, Date timeOfCreation) {
        this.exportedKeyData = exportedKeyData;
        this.decryptionCode = decryptionCode;
        this.verificationCode = verificationCode;
        this.outputFilePath = outputFilePath;
        this.timeOfCreation = timeOfCreation;
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
