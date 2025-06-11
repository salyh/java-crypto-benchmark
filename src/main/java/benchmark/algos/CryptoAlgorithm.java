package benchmark.algos;

// Pluggable algorithm interface

/**
 * DO NOT USE THIS CLASS IN PRODUCTION!
 */
public interface CryptoAlgorithm {

    //WARNING: DO NOT USE THIS IN PRODUCTION CODE!
    //Hardcoded keys for testing purposes only.
    byte[] DUMMY_KEY_BYTES_32 = new byte[]{0, 1, 2, 3, 4, 5, 6, 7,
            8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31};

    static CryptoAlgorithm newInstanceFor(String algorithm) {
        if ("AES_GCM".equals(algorithm)) {
            return new AesGcmAlgorithm();
        } else if ("AES_CTR".equals(algorithm)) {
            return new AesCtrAlgorithm();
        } else if ("CHACHA20_POLY1305".equals(algorithm)) {
            return new ChaCha20Poly1305Algorithm();
        } else if ("LibsodiumXCHACHA20_POLY1305".equals(algorithm)) {
            return new LibsodiumXChaCha20Poly1305Algorithm();
        } else if ("LibsodiumAES_GCM".equals(algorithm)) {
            return new LibsodiumAesGcmAlgorithm();
        } else if ("OpenSslPanamaAES_CTR".equals(algorithm)) {
            return new OpenSslPanamaAesCtrAlgorithm();
        } else if ("OpenSslPanamaAES_GCM".equals(algorithm)) {
            return new OpenSslPanamaAesGcmAlgorithm();
        } else if ("Null".equals(algorithm)) {
            return new NullAlgorithm();
        } else {
            throw new IllegalArgumentException("Unknown algorithm: " + algorithm);
        }
    }

    void init() throws Exception;

    void reInit() throws Exception;

    byte[] encrypt(byte[] data, int inputLen, boolean lastEncyptionChunk) throws Exception;

    byte[] decrypt(byte[] data, int inputLen, boolean lastEncyptionChunk) throws Exception;

    int tagLen();
}
