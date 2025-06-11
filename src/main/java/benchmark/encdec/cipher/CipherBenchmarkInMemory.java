package benchmark.encdec.cipher;

import benchmark.algos.CryptoAlgorithm;
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

import java.security.SecureRandom;
import java.util.Arrays;
import java.util.concurrent.TimeUnit;

/**
 * In-Memory cipher benchmark
 */
@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.MILLISECONDS)
@State(Scope.Benchmark)
@Warmup(iterations = 4, time = 5, timeUnit = TimeUnit.SECONDS)
@Measurement(iterations = 5, time = 15, timeUnit = TimeUnit.SECONDS)
@Fork(1)
@Threads(1)
public class CipherBenchmarkInMemory {

    private final static SecureRandom SECURE_RANDOM = new SecureRandom();

    private byte[] BYTES_RAND_1;
    private byte[] BYTES_RAND_2;
    private byte[] BYTES_RAND_3;
    private byte[] BYTES_RAND_4;

    @Param({"OpenSslPanamaAES_GCM", "OpenSslPanamaAES_CTR", "LibsodiumAES_GCM", "LibsodiumXCHACHA20_POLY1305", "AES_GCM", "AES_CTR", "CHACHA20_POLY1305"})
    String algorithm;

    @Param({"16384", "65536", "786432", "1048576", "2097152", "4194304", "7868416"})
    int dataSize; //can be considered also the chunk size

    private CryptoAlgorithm cryptoAlgorithm = null;


    @Benchmark
    public void cryptInMemory(Blackhole bh) throws Exception {
        byte[] encrypted1 = cryptoAlgorithm.encrypt(BYTES_RAND_1, BYTES_RAND_1.length, false);
        byte[] encrypted2 = cryptoAlgorithm.encrypt(BYTES_RAND_2, BYTES_RAND_2.length, false);
        byte[] encrypted3 = cryptoAlgorithm.encrypt(BYTES_RAND_3, BYTES_RAND_3.length, false);
        byte[] encrypted4 = cryptoAlgorithm.encrypt(BYTES_RAND_4, BYTES_RAND_4.length, true);

        byte[] decrypted1 = cryptoAlgorithm.decrypt(encrypted1, encrypted1.length, false);
        byte[] decrypted2 = cryptoAlgorithm.decrypt(encrypted2, encrypted2.length, false);
        byte[] decrypted3 = cryptoAlgorithm.decrypt(encrypted3, encrypted3.length, false);
        byte[] decrypted4 = cryptoAlgorithm.decrypt(encrypted4, encrypted4.length, true);

        if (decrypted1.length == 0) {
            if (!Arrays.equals(decrypted4, concat(BYTES_RAND_1, BYTES_RAND_2, BYTES_RAND_3, BYTES_RAND_4))) {
                throw new Exception("Decrypted data not match original");
            }
        } else {

            if (!Arrays.equals(decrypted1, BYTES_RAND_1)) {
                throw new Exception("Decrypted data 1 not match original");
            }

            if (!Arrays.equals(decrypted2, BYTES_RAND_2)) {
                throw new Exception("Decrypted data 2 not match original");
            }

            if (!Arrays.equals(decrypted3, BYTES_RAND_3)) {
                throw new Exception("Decrypted data 3 not match original");
            }

            if (!Arrays.equals(decrypted4, BYTES_RAND_4)) {
                throw new Exception("Decrypted data 4 not match original");
            }
        }

        bh.consume(decrypted1);
        bh.consume(decrypted2);
        bh.consume(decrypted3);
        bh.consume(decrypted4);

        cryptoAlgorithm.reInit();

    }


    @Setup(Level.Trial)
    public void setUp() throws Exception {
        System.out.println("Setting up benchmark with algorithm: " + algorithm + " and data size: " + dataSize);

        BYTES_RAND_1 = new byte[dataSize];
        BYTES_RAND_2 = new byte[dataSize];
        BYTES_RAND_3 = new byte[dataSize];
        BYTES_RAND_4 = new byte[dataSize - 1000]; // last chunk is smaller

        SECURE_RANDOM.nextBytes(BYTES_RAND_1);
        SECURE_RANDOM.nextBytes(BYTES_RAND_2);
        SECURE_RANDOM.nextBytes(BYTES_RAND_3);
        SECURE_RANDOM.nextBytes(BYTES_RAND_4);

        cryptoAlgorithm = CryptoAlgorithm.newInstanceFor(algorithm);
        cryptoAlgorithm.init();
    }

    private static byte[] concat(byte[]... arrays) {
        int totalLength = 0;
        for (byte[] array : arrays) {
            totalLength += array.length;
        }

        byte[] result = new byte[totalLength];
        int currentPos = 0;

        for (byte[] array : arrays) {
            System.arraycopy(array, 0, result, currentPos, array.length);
            currentPos += array.length;
        }

        return result;
    }

}