package benchmark.algos;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.util.concurrent.atomic.AtomicLong;

/**
 * DO NOT USE THIS CLASS IN PRODUCTION!
 */
public class AesGcmAlgorithm implements CryptoAlgorithm {

    private Cipher enccipher = null;
    private Cipher deccipher = null;
    SecretKeySpec keySpec = new SecretKeySpec(DUMMY_KEY_BYTES_32, "AES");

    private AtomicLong counter;

    @Override
    public void init() throws Exception {
        counter = new AtomicLong(0);
        byte[] iv = generateIv();
        enccipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec ivSpec = new GCMParameterSpec(128, iv);
        enccipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);

        deccipher = Cipher.getInstance("AES/GCM/NoPadding");
        ivSpec = new GCMParameterSpec(128, iv);
        deccipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);
        //System.out.println("IV init "+ Arrays.toString(iv) + " for counter: " + counter.get());
    }

    @Override
    public void reInit() throws Exception {
        byte[] iv = generateIv();
        GCMParameterSpec ivSpec = new GCMParameterSpec(128, iv);
        enccipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);

        ivSpec = new GCMParameterSpec(128, iv);
        deccipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);
        //System.out.println("IV reinit "+ Arrays.toString(iv) + " for counter: " + counter.get());

    }

    @Override
    public byte[] encrypt(byte[] data, int inputLen, boolean last) throws Exception {
        //System.out.println("Encrypt "+ Arrays.toString(data) + " with length " + inputLen + " and last chunk flag: " + last+ " counter: " + counter.get());

        byte[] encrypted = null;
        if (last) {
            // If this is the last chunk, finalize the encryption
            encrypted = enccipher.doFinal(data, 0, inputLen);
        } else {
            // Otherwise, just update the cipher with the data
            encrypted = enccipher.update(data, 0, inputLen);
        }
        //System.out.println("Encrypt res "+ Arrays.toString(encrypted));

        return encrypted;
    }

    @Override
    public byte[] decrypt(byte[] data, int inputLen, boolean last) throws Exception {
        //System.out.println("Decrypt "+ Arrays.toString(data) + " with length " + inputLen + " and last chunk flag: " + last+ " counter: " + counter.get());

        byte[] decrypted = null;
        if (last) {
            // If this is the last chunk, finalize the encryption
            decrypted = deccipher.doFinal(data, 0, inputLen);
        } else {
            // Otherwise, just update the cipher with the data
            decrypted = deccipher.update(data, 0, inputLen);
        }
        //System.out.println("decrypt res "+ Arrays.toString(decrypted));

        return decrypted;
    }

    @Override
    public int tagLen() {
        return 16;
    }

    private byte[] generateIv() {
        ByteBuffer buffer = ByteBuffer.allocate(12); // 96-bit IV for GCM
        buffer.putLong(4, counter.getAndIncrement()); // Put counter in the last 8 bytes
        return buffer.array();
    }

}
