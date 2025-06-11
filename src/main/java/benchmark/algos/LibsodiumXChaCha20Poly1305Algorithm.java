package benchmark.algos;

import benchmark.ciphers.libsodium.LibsodiumXChaCha20Poly1305;

import java.nio.ByteBuffer;
import java.util.concurrent.atomic.AtomicLong;

/**
 * DO NOT USE THIS CLASS IN PRODUCTION!
 */
public class LibsodiumXChaCha20Poly1305Algorithm implements CryptoAlgorithm {

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
        return LibsodiumXChaCha20Poly1305.encryptOneShot(DUMMY_KEY_BYTES_32, iv, data, inputLen);
    }

    @Override
    public byte[] decrypt(byte[] data, int inputLen, boolean last) throws Exception {
        return LibsodiumXChaCha20Poly1305.decryptOneShot(DUMMY_KEY_BYTES_32, iv, data, inputLen);
    }

    @Override
    public int tagLen() {
        return 16;
    }

    private byte[] generateIv() {
        ByteBuffer buffer = ByteBuffer.allocate(24); // 192-bit IV
        buffer.putLong(4, counter.getAndIncrement()); // Put counter in the last 8 bytes
        return buffer.array();
    }


}
