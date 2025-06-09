package benchmark.encdec.file;

import org.apache.tuweni.crypto.sodium.AES256GCM;
import org.apache.tuweni.crypto.sodium.LibSodium;
import org.apache.tuweni.crypto.sodium.Sodium;
import org.apache.tuweni.crypto.sodium.XChaCha20Poly1305;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.BenchmarkMode;
import org.openjdk.jmh.annotations.Fork;
import org.openjdk.jmh.annotations.Level;
import org.openjdk.jmh.annotations.Measurement;
import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.annotations.OutputTimeUnit;
import org.openjdk.jmh.annotations.Param;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;
import org.openjdk.jmh.annotations.Threads;
import org.openjdk.jmh.annotations.Warmup;
import org.openjdk.jmh.infra.Blackhole;
import org.openjdk.jmh.results.RunResult;
import org.openjdk.jmh.runner.Runner;
import org.openjdk.jmh.runner.RunnerException;
import org.openjdk.jmh.runner.options.Options;
import org.openjdk.jmh.runner.options.OptionsBuilder;

import javax.crypto.Cipher;
import javax.crypto.spec.ChaCha20ParameterSpec;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Comprehensive cryptographic benchmark for large file encryption/decryption
 * using Java Microbenchmark Harness (JMH).
 *
 * Supports files up to 5TB with chunked processing to avoid memory limitations.
 * Uses counter-based IV/nonces for reproducible results.
 */
@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.MILLISECONDS)
@State(Scope.Benchmark)
@Warmup(iterations = 5, time = 5, timeUnit = TimeUnit.SECONDS)
@Measurement(iterations = 5, time = 10, timeUnit = TimeUnit.SECONDS)
@Fork(1)
@Threads(1)
public class CipherBenchmark {

    private final static byte[] BYTES_32 = new byte[]{0, 1, 2, 3, 4, 5, 6, 7,
            8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31};

    private final static byte[] BYTES_RAND_1 = new byte[(7684*1024)/*+1*/]; //TODO check non multiples
    private final static byte[] BYTES_RAND_2 = new byte[7684*1024];
    private final static byte[] BYTES_RAND_3 = new byte[7684*1024];
    private final static byte[] BYTES_RAND_4 = new byte[(500*1000)+1];


    static {
        // Fill BYTES_RAND with random data
        new SecureRandom().nextBytes(BYTES_RAND_1);
        new SecureRandom().nextBytes(BYTES_RAND_2);
        new SecureRandom().nextBytes(BYTES_RAND_3);
        new SecureRandom().nextBytes(BYTES_RAND_4);
    }

    @Param({"TuweniAES_GCM","TuweniXCHACHA20_POLY1305", "AES_GCM", "AES_CTR", "CHACHA20_POLY1305"})
    String algorithm;


    public static void main(String[] args) throws RunnerException {
        Options opt = new OptionsBuilder()
                .include(CipherBenchmark.class.getSimpleName())
                .build();

        Collection<RunResult> results = new Runner(opt).run();
    }

    private CryptoAlgorithm cryptoAlgorithm = null;

    @Benchmark
    public void crypt(Blackhole bh) throws Exception {
        byte[] encrypted1 = cryptoAlgorithm.encrypt(BYTES_RAND_1, false);
        byte[] encrypted2 = cryptoAlgorithm.encrypt(BYTES_RAND_2, false);
        byte[] encrypted3 = cryptoAlgorithm.encrypt(BYTES_RAND_3, false);
        byte[] encrypted4 = cryptoAlgorithm.encrypt(BYTES_RAND_4, true);

        //assert encrypted1.length == BYTES_RAND_1.length;
        //assert encrypted2.length == BYTES_RAND_2.length;
        //assert encrypted3.length == BYTES_RAND_3.length;
        //assert encrypted4.length == BYTES_RAND_4.length + cryptoAlgorithm.tagLen(); // GCM tag is 16 bytes

        byte[] decrypted1 = cryptoAlgorithm.decrypt(encrypted1, false);
        byte[] decrypted2 = cryptoAlgorithm.decrypt(encrypted2, false);
        byte[] decrypted3 = cryptoAlgorithm.decrypt(encrypted3, false);
        byte[] decrypted4 = cryptoAlgorithm.decrypt(encrypted4, true);

        /*System.out.println("Decrypted lengths: " +
                decrypted1.length + ", " +
                decrypted2.length + ", " +
                decrypted3.length + ", " +
                decrypted4.length);*/

        assert decrypted1.length + decrypted2.length + decrypted3.length + decrypted4.length ==
                BYTES_RAND_1.length + BYTES_RAND_2.length + BYTES_RAND_3.length + BYTES_RAND_4.length;


        //GCM
        //assert decrypted1.length == 0;
        //assert decrypted2.length == 0;
        //assert decrypted3.length == 0;
        //assert decrypted4.length == BYTES_RAND_1.length + BYTES_RAND_2.length + BYTES_RAND_3.length + BYTES_RAND_4.length;

        //CTR
        //respective msg len

        bh.consume(decrypted1);
        bh.consume(decrypted2);
        bh.consume(decrypted3);
        bh.consume(decrypted4);

        cryptoAlgorithm.reInit();

    }


    @Setup(Level.Trial)
    public void setUp() throws Exception {
        if ("AES_GCM".equals(algorithm)) {
            cryptoAlgorithm = new AesGcmAlgorithm();
        } else if ("AES_CTR".equals(algorithm)) {
            cryptoAlgorithm = new AesCtrAlgorithm();
        } else if ("CHACHA20_POLY1305".equals(algorithm)) {
            cryptoAlgorithm = new ChaCha20Poly1305Algorithm();
        } else if ("TuweniXCHACHA20_POLY1305".equals(algorithm)) {
            cryptoAlgorithm = new TuweniXChaCha20Poly1305Algorithm();
        } else if ("TuweniAES_GCM".equals(algorithm)) {
            cryptoAlgorithm = new TuweniAesGcmAlgorithm();
        } else {
            throw new IllegalArgumentException("Unknown algorithm: " + algorithm);
        }
        cryptoAlgorithm.init();
    }


    // Pluggable algorithm interface
    interface CryptoAlgorithm {
        void init() throws Exception;
        void reInit() throws Exception;
        byte[] encrypt(byte[] data, boolean last) throws Exception;
        byte[] decrypt(byte[] data, boolean last) throws Exception;
        int tagLen();
    }


    static class AesGcmAlgorithm implements CryptoAlgorithm {

        private Cipher enccipher = null;
        private Cipher deccipher = null;
        SecretKeySpec keySpec = new SecretKeySpec(BYTES_32, "AES");

        private AtomicLong counter = new AtomicLong(0);

        @Override
        public void init() throws Exception {
            byte[] iv = generateIv();
            enccipher = Cipher.getInstance("AES/GCM/NoPadding");
            GCMParameterSpec ivSpec = new GCMParameterSpec(128, iv);
            enccipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);

            deccipher = Cipher.getInstance("AES/GCM/NoPadding");
            ivSpec = new GCMParameterSpec(128, iv);
            deccipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);
        }

        @Override
        public void reInit() throws Exception {
            byte[] iv = generateIv();
            GCMParameterSpec ivSpec = new GCMParameterSpec(128, iv);
            enccipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);

            ivSpec = new GCMParameterSpec(128, iv);
            deccipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);
        }

        @Override
        public byte[] encrypt(byte[] data, boolean last) throws Exception {
            byte[] encrypted = null;
            if(last) {
                // If this is the last chunk, finalize the encryption
                encrypted = enccipher.doFinal(data);
            } else {
                // Otherwise, just update the cipher with the data
                encrypted = enccipher.update(data);
            }

            return encrypted;
        }

        @Override
        public byte[] decrypt(byte[] data, boolean last) throws Exception {
            byte[] decrypted = null;
            if(last) {
                // If this is the last chunk, finalize the encryption
                decrypted = deccipher.doFinal(data);
            } else {
                // Otherwise, just update the cipher with the data
                decrypted = deccipher.update(data);
            }

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

    static class AesCtrAlgorithm implements CryptoAlgorithm {

        private Cipher enccipher = null;
        private Cipher deccipher = null;
        SecretKeySpec keySpec = new SecretKeySpec(BYTES_32, "AES");

        private AtomicLong counter = new AtomicLong(0);

        @Override
        public void init() throws Exception {
            byte[] iv = generateIv();
            enccipher = Cipher.getInstance("AES/CTR/NoPadding");
            IvParameterSpec ivSpec = new IvParameterSpec(iv);
            enccipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);

            deccipher = Cipher.getInstance("AES/CTR/NoPadding");
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
        public byte[] encrypt(byte[] data, boolean last) throws Exception {
            byte[] encrypted = null;
            if(last) {
                // If this is the last chunk, finalize the encryption
                encrypted = enccipher.doFinal(data);
            } else {
                // Otherwise, just update the cipher with the data
                encrypted = enccipher.update(data);
            }

            return encrypted;
        }

        @Override
        public byte[] decrypt(byte[] data, boolean last) throws Exception {
            byte[] decrypted = null;
            if(last) {
                // If this is the last chunk, finalize the encryption
                decrypted = deccipher.doFinal(data);
            } else {
                // Otherwise, just update the cipher with the data
                decrypted = deccipher.update(data);
            }

            return decrypted;
        }

        @Override
        public int tagLen() {
            return 0;
        }

        private byte[] generateIv() {
            ByteBuffer buffer = ByteBuffer.allocate(16); // 128-bit IV for CTR
            buffer.putLong(4, counter.getAndIncrement()); // Put counter in the last 8 bytes
            return buffer.array();
        }

    }

    static class ChaCha20Poly1305Algorithm implements CryptoAlgorithm {

        private Cipher enccipher = null;
        private Cipher deccipher = null;
        SecretKeySpec keySpec = new SecretKeySpec(BYTES_32, "ChaCha20");

        private AtomicLong counter = new AtomicLong(0);

        @Override
        public void init() throws Exception {
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
        public byte[] encrypt(byte[] data, boolean last) throws Exception {
            byte[] encrypted = null;
            if(last) {
                // If this is the last chunk, finalize the encryption
                encrypted = enccipher.doFinal(data);
            } else {
                // Otherwise, just update the cipher with the data
                encrypted = enccipher.update(data);
            }

            return encrypted;
        }

        @Override
        public byte[] decrypt(byte[] data, boolean last) throws Exception {
            byte[] decrypted = null;
            if(last) {
                // If this is the last chunk, finalize the encryption
                decrypted = deccipher.doFinal(data);
            } else {
                // Otherwise, just update the cipher with the data
                decrypted = deccipher.update(data);
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

    static class TuweniXChaCha20Poly1305Algorithm implements CryptoAlgorithm {

        static {
            if(!Sodium.isAvailable()) {
                Sodium.loadLibrary(Paths.get("/opt/homebrew/lib/libsodium.dylib"));
            }
        }

        private final XChaCha20Poly1305.Key key = XChaCha20Poly1305.Key.random();
        private final XChaCha20Poly1305.Nonce nonce = XChaCha20Poly1305.Nonce.random();

        @Override
        public void init() throws Exception {
            System.out.println("Sodium version: "+Sodium.version());
            if(!XChaCha20Poly1305.isAvailable()){
                throw new IllegalStateException("XChaCha20Poly1305 is not available");
            }
        }

        @Override
        public void reInit() throws Exception {

        }

        @Override
        public byte[] encrypt(byte[] data, boolean last) throws Exception {
            return XChaCha20Poly1305.encrypt(data, key, nonce);
        }

        @Override
        public byte[] decrypt(byte[] data, boolean last) throws Exception {
            return XChaCha20Poly1305.decrypt(data, key, nonce);
        }

        @Override
        public int tagLen() {
            return 16;
        }

    }

    static class TuweniAesGcmAlgorithm implements CryptoAlgorithm {

        static {
            if(!Sodium.isAvailable()) {
                Sodium.loadLibrary(Paths.get("/opt/homebrew/lib/libsodium.dylib"));
            }
        }

        private final AES256GCM.Key key = AES256GCM.Key.random();
        private final AES256GCM.Nonce nonce = AES256GCM.Nonce.random();

        @Override
        public void init() throws Exception {
            System.out.println("Sodium version: "+Sodium.version());
            if(!AES256GCM.isAvailable()){
                throw new IllegalStateException("AES256GCM is not available");
            }
        }

        @Override
        public void reInit() throws Exception {

        }

        @Override
        public byte[] encrypt(byte[] data, boolean last) throws Exception {
            return AES256GCM.encrypt(data, key, nonce);
        }

        @Override
        public byte[] decrypt(byte[] data, boolean last) throws Exception {
            return AES256GCM.decrypt(data, key, nonce);
        }

        @Override
        public int tagLen() {
            return 16;
        }

    }

}