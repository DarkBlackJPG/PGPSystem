package etf.openpgp.ts170124dss170372d.ExceptionPackage;

public class NullObjectException extends Exception {
    private String exceptionMessage = "Null object reference";

    public NullObjectException() {
        super();
    }

    public NullObjectException(String message) {
        super(message);
        exceptionMessage = message;
    }

    @Override
    public String getMessage() {
        return exceptionMessage;
    }
}
