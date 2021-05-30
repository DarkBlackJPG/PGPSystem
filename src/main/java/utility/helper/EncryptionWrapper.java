package utility.helper;

public class EncryptionWrapper {
    private utility.KeyManager.ExportedKeyData element;
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

    public utility.KeyManager.ExportedKeyData getElement() {
        return element;
    }

    public void setElement(utility.KeyManager.ExportedKeyData element) {
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
