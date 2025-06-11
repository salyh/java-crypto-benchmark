package benchmark.ciphers.libsodium;

public class LibsodiumException extends RuntimeException {

    public LibsodiumException(Throwable cause) {
        super(cause);
    }

    public LibsodiumException(String message) {
        super(message);
    }

    public LibsodiumException(String message, Throwable cause) {
        super(message, cause);
    }
}
