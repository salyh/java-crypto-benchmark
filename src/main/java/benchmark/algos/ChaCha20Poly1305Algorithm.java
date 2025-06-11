package benchmark.algos;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.util.concurrent.atomic.AtomicLong;

/**
 * DO NOT USE THIS CLASS IN PRODUCTION!
 */
public class ChaCha20Poly1305Algorithm implements CryptoAlgorithm {

    private Cipher enccipher = null;
    private Cipher deccipher = null;
    SecretKeySpec keySpec = new SecretKeySpec(DUMMY_KEY_BYTES_32, "ChaCha20");

    private AtomicLong counter;

    @Override
    public void init() throws Exception {
        counter = new AtomicLong(0);
        byte[] iv = generateIv();
        enccipher = Cipher.getInstance("ChaCha20-Poly1305");
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        enccipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);

        deccipher = Cipher.getInstance("ChaCha20-Poly1305");
        ivSpec = new IvParameterSpec(iv);
        deccipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);
    }

    @Override
    public void reInit() throws Exception {
        byte[] iv = generateIv();
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        enccipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);

        ivSpec = new IvParameterSpec(iv);
        deccipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);
    }

    @Override
    public byte[] encrypt(byte[] data, int inputLen, boolean last) throws Exception {
        byte[] encrypted = null;
        if (last) {
            // If this is the last chunk, finalize the encryption
            encrypted = enccipher.doFinal(data, 0, inputLen);
        } else {
            // Otherwise, just update the cipher with the data
            encrypted = enccipher.update(data, 0, inputLen);
        }

        return encrypted;
    }

    @Override
    public byte[] decrypt(byte[] data, int inputLen, boolean last) throws Exception {
        byte[] decrypted = null;
        if (last) {
            // If this is the last chunk, finalize the encryption
            decrypted = deccipher.doFinal(data, 0, inputLen);
        } else {
            // Otherwise, just update the cipher with the data
            decrypted = deccipher.update(data, 0, inputLen);
        }

        return decrypted;
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
