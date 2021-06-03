package etf.openpgp.ts170124dss170372d.ExceptionPackage;

public class KeyNotFoundException extends Exception{
    private String exceptionMessage = "Key with the given KeyId is not found! Check if using hexadecimal format and if the KeyID is correct";

    public KeyNotFoundException() {
        super();
    }

    public KeyNotFoundException(String message) {
        super(message);
        exceptionMessage = message;
    }

    @Override
    public String getMessage() {
        return exceptionMessage;
    }
}
