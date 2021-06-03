package etf.openpgp.ts170124dss170372d.utility.KeyManager;

import java.util.Date;

public class ExportedKeyData {
    private boolean isMasterKey;
    private String userName;
    private String email;
    private Date validFrom;
    private Date validUntil;
    private long keyID;

    public boolean getIsMasterKey() {
        return isMasterKey;
    }

    public void setMasterKey(boolean masterKey) {
        isMasterKey = masterKey;
    }

    public String getUserName() {
        return userName;
    }

    public void setUserName(String userName) {
        this.userName = userName;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public Date getValidFrom() {
        return validFrom;
    }

    public void setValidFrom(Date validFrom) {
        this.validFrom = validFrom;
    }

    public Date getValidUntil() {
        return validUntil;
    }

    public void setValidUntil(Date validUntil) {
        this.validUntil = validUntil;
    }

    public long getKeyID() {
        return keyID;
    }

    public String getKeyIDHex() {
        return Long.toHexString(keyID).toUpperCase();
    }

    public void setKeyID(long keyID) {
        this.keyID = keyID;
    }

    @Override
    public String toString() {
        return "ExportedKeyData{" +
                "isMasterKey=" + isMasterKey +
                ", userName='" + userName + '\'' +
                ", email='" + email + '\'' +
                ", validFrom=" + validFrom +
                ", validUntil=" + validUntil +
                ", keyID=" + Long.toHexString(keyID) +
                '}';
    }
}
