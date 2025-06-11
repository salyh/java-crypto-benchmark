package benchmark.algos;

import benchmark.ciphers.openssl.OpenSslPanamaGcmCipher;

import java.nio.ByteBuffer;
import java.util.concurrent.atomic.AtomicLong;

/**
 * DO NOT USE THIS CLASS IN PRODUCTION!
 */
public class OpenSslPanamaAesGcmAlgorithm implements CryptoAlgorithm {

    private AtomicLong counter;

    private byte[] iv = null;

    @Override
    public void init() throws Exception {
        counter = new AtomicLong(0);
        iv = generateIv();
    }

    @Override
    public void reInit() throws Exception {
        iv = generateIv();
    }

    @Override
    public byte[] encrypt(byte[] data, int inputLen, boolean last) throws Exception {
        try {
            return OpenSslPanamaGcmCipher.encryptOneShot(DUMMY_KEY_BYTES_32, iv, data, inputLen);
        } catch (Throwable e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public byte[] decrypt(byte[] data, int inputLen, boolean last) throws Exception {
        try {
            return OpenSslPanamaGcmCipher.decryptOneShot(DUMMY_KEY_BYTES_32, iv, data, inputLen);
        } catch (Throwable e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public int tagLen() {
        return 16;
    }

    private byte[] generateIv() {
        ByteBuffer buffer = ByteBuffer.allocate(12); // 96-bit IV
        buffer.putLong(4, counter.getAndIncrement()); // Put counter in the last 8 bytes
        return buffer.array();
    }

}
