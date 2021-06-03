package etf.openpgp.ts170124dss170372d.ExceptionPackage;

public class IncorrectKeyException extends Exception {
    private String exceptionMessage = "Incorrect key provided!";

    public IncorrectKeyException() {
        super();
    }

    public IncorrectKeyException(String message) {
        super(message);
        exceptionMessage = message;
    }

    @Override
    public String getMessage() {
        return exceptionMessage;
    }
}
