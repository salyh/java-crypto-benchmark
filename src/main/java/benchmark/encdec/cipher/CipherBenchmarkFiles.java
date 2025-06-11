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
import org.openjdk.jmh.annotations.TearDown;
import org.openjdk.jmh.annotations.Threads;
import org.openjdk.jmh.annotations.Warmup;
import org.openjdk.jmh.infra.Blackhole;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.FileInputStream;
import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.SecureRandom;
import java.util.concurrent.TimeUnit;

/**
 * File-based cipher benchmark
 */
@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.MILLISECONDS)
@State(Scope.Benchmark)
@Warmup(iterations = 4, time = 5, timeUnit = TimeUnit.SECONDS)
@Measurement(iterations = 5, time = 15, timeUnit = TimeUnit.SECONDS)
@Fork(1)
@Threads(1)
public class CipherBenchmarkFiles {

    private static final int WRITE_BUFFER_SIZE = 8192;

    @Param({"OpenSslPanamaAES_GCM", "OpenSslPanamaAES_CTR", "LibsodiumAES_GCM", "LibsodiumXCHACHA20_POLY1305", "AES_GCM", "AES_CTR", "CHACHA20_POLY1305"})
    String algorithm;


    @Param({"100000", "1000000", "4000000", "50000000", "1000000000"})
    //~100kb, ~1Mb, ~4Mb, ~50Mb, ~1Gb
    long fileSize;

    @Param({"16384", "65536", "786432", "1048576", "2097152", "4194304", "7868416"})
    int encryptionChunkSize;

    private CryptoAlgorithm cryptoAlgorithm = null;

    private OutputStream buffer(OutputStream delegate) {
        return new BufferedOutputStream(new FilterOutputStream(delegate) {
            @Override
            public void write(byte[] b, int offset, int length) throws IOException {
                while (length > 0) {
                    final int chunk = Math.min(length, WRITE_BUFFER_SIZE);
                    out.write(b, offset, chunk);
                    length -= chunk;
                    offset += chunk;
                }
            }
        }, WRITE_BUFFER_SIZE);

    }

    private void generateTestFile(Path file, long size) throws Exception {
        if (Files.exists(file)) {
            return;
        }
        System.out.println("Generating test cipher: " + file + " (" + size + ")");

        try (var channel = Files.newByteChannel(file,
                StandardOpenOption.CREATE,
                StandardOpenOption.WRITE,
                StandardOpenOption.TRUNCATE_EXISTING)) {

            SecureRandom random = new SecureRandom();
            byte[] buffer = new byte[8 * 1024];
            long remaining = size;
            long processed = 0;

            while (remaining > 0) {
                int chunkSize = (int) Math.min(buffer.length, remaining);
                random.nextBytes(buffer);
                channel.write(ByteBuffer.wrap(buffer, 0, chunkSize));
                remaining -= chunkSize;
                processed += chunkSize;

                // Progress indicator for large files
                if (processed % (1024L * 1024 * 1024) == 0) { // Every GB
                    System.out.printf("Generated %.2f GB / %.2f GB%n",
                            processed / (1024.0 * 1024 * 1024),
                            size / (1024.0 * 1024 * 1024));
                }
            }
        }

        System.out.println("Test cipher generation completed: " + size);
    }

    void checkFileNotEmpty(Path file) throws Exception {
        if (Files.size(file) == 0) {
            throw new Exception("File is empty: " + file);
        }
    }


    @Benchmark
    public void cryptFile(Blackhole bh) throws Exception {
        cryptoAlgorithm.init();

        final Path plainTextFile = Paths.get("test_file_" + fileSize + ".bin");
        final Path encryptedFile = Paths.get("test_file_" + fileSize + ".bin-" + cryptoAlgorithm.getClass().getName() + ".enc");
        final Path decryptedFile = Paths.get("test_file_" + fileSize + ".bin-" + cryptoAlgorithm.getClass().getName() + ".dec");


        checkFileNotEmpty(plainTextFile);

        encryptFile(plainTextFile, encryptedFile, 8192, encryptionChunkSize);

        checkFileNotEmpty(encryptedFile);

        cryptoAlgorithm.init(); // do not call reInit(), we need to reset the nonce too for decryption

        decryptFile(encryptedFile, decryptedFile, 16384, encryptionChunkSize);

        checkFileNotEmpty(decryptedFile);


    }

    public long filesCompareByByte(Path path1, Path path2) throws Exception {

        if (!Files.exists(path1)) {
            return -1L;
        }

        checkFileNotEmpty(path1);

        try (BufferedInputStream fis1 = new BufferedInputStream(new FileInputStream(path1.toFile()));
             BufferedInputStream fis2 = new BufferedInputStream(new FileInputStream(path2.toFile()))) {

            int ch = 0;
            long pos = 1;
            while ((ch = fis1.read()) != -1) {
                if (ch != fis2.read()) {
                    return pos;
                }
                pos++;
            }
            if (fis2.read() == -1) {
                return -1;
            } else {
                return pos;
            }
        }
    }

    public void encryptFile(Path source, Path dest, int inputBufferSize, int encryptionChunkSize) throws Exception {

        final boolean isAead = cryptoAlgorithm.tagLen() > 0;

        try (var input = new BufferedInputStream(Files.newInputStream(source, StandardOpenOption.READ), inputBufferSize);
             var output = buffer(Files.newOutputStream(dest, StandardOpenOption.WRITE, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING))) {

            byte[] buf = new byte[encryptionChunkSize];
            int length;
            while ((length = input.read(buf)) != -1) {

                if (length == 0) {
                    continue; // Skip empty reads
                }

                //only aead algorithms need to call doFinal()
                //no multipart, just one-shot with encryptionChunkSize
                byte[] encrypted = cryptoAlgorithm.encrypt(buf, length, isAead);

                if (isAead) {
                    if (encrypted == null) {
                        throw new IOException("AEAD encryption failed, encrypted data is null");
                    }
                    if (encrypted.length == 0) {
                        throw new IOException("AEAD encryption failed, expected no empty encrypted data for last chunk");
                    }
                } else {
                    if (encrypted == null) {
                        throw new IOException("Encryption failed, encrypted data is null");
                    }
                    if (encrypted.length == 0) {
                        throw new IOException("Encryption failed, expected no empty encrypted data for last chunk");
                    }
                }

                if (encrypted.length > 0) {
                    output.write(encrypted);
                }

                cryptoAlgorithm.reInit();
            }
        }


    }

    public void decryptFile(Path source, Path dest, int inputBufferSize, int encryptionChunkSize) throws Exception {

        final boolean isAead = cryptoAlgorithm.tagLen() > 0;

        try (var input = new BufferedInputStream(Files.newInputStream(source, StandardOpenOption.READ), inputBufferSize);
             var output = buffer(Files.newOutputStream(dest, StandardOpenOption.WRITE, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING))) {

            byte[] buf = new byte[encryptionChunkSize + cryptoAlgorithm.tagLen()];
            int length;
            while ((length = input.read(buf)) != -1) {

                if (length == 0) {
                    continue; // Skip empty reads
                }

                //only aead algorithms need to call doFinal()
                //no multipart, just one-shot with encryptionChunkSize
                byte[] decrypted = cryptoAlgorithm.decrypt(buf, length, isAead);

                if (isAead) {
                    if (decrypted == null) {
                        throw new IOException("AEAD encryption failed, decrypted data is null");
                    }
                    if (decrypted.length == 0) {
                        throw new IOException("AEAD encryption failed, expected no empty decrypted data for last chunk");
                    }
                } else {
                    if (decrypted == null) {
                        throw new IOException("Encryption failed, decrypted data is null");
                    }
                    if (decrypted.length == 0) {
                        throw new IOException("Encryption failed, expected no empty decrypted data for last chunk");
                    }
                }

                if (decrypted.length > 0) {
                    output.write(decrypted);
                }

                cryptoAlgorithm.reInit();
            }
        }


    }

    @TearDown(Level.Iteration)
    public void tearDown() throws Exception {

        final Path plainTextFile = Paths.get("test_file_" + fileSize + ".bin");
        final Path decryptedFile = Paths.get("test_file_" + fileSize + ".bin-" + cryptoAlgorithm.getClass().getName() + ".dec");


        if (filesCompareByByte(decryptedFile, plainTextFile) != -1L) {
            throw new IOException("Decrypted cipher does not match original cipher");
        }
    }

    @Setup(Level.Trial)
    public void setUp() throws Exception {
        System.out.println("Setting up benchmark with algorithm: " + algorithm + ", cipher size: " + fileSize + ", chunk size: " + encryptionChunkSize);
        cryptoAlgorithm = CryptoAlgorithm.newInstanceFor(algorithm);
        generateTestFile(Paths.get("test_file_" + fileSize + ".bin"), fileSize);
    }


}