package etf.openpgp.ts170124dss170372d.utility.helper;

import etf.openpgp.ts170124dss170372d.utility.KeyManager.ExportedKeyData;

public class EncryptionWrapper {
    private ExportedKeyData element;
    private boolean isSelected;

    public String getUserName() {
        return element.getUserName();
    }

    public long getKeyID() {
        return  element.getKeyID();
    }
    public String getKeyIDHex() {
        return  Long.toHexString(element.getKeyID()).toUpperCase();
    }

    public String getEmail() {
        return element.getEmail();
    }

    public ExportedKeyData getElement() {
        return element;
    }

    public void setElement(ExportedKeyData element) {
        this.element = element;
    }

    public boolean isSelected() {
        return isSelected;
    }

    public void setSelected(boolean selected) {
        isSelected = selected;
    }

    @Override
    public String toString() {
        return "EncryptionWrapper{" +
                "element=" + element +
                ", isSelected=" + isSelected +
                '}';
    }
}
