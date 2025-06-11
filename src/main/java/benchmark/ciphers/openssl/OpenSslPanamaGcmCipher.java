package benchmark.ciphers.openssl;

import java.lang.foreign.Arena;
import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.Linker;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.SymbolLookup;
import java.lang.foreign.ValueLayout;
import java.lang.invoke.MethodHandle;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Locale;

/**
 * Based on the work of the OpenSearch project (kumargu)
 * Originally licensed under the Apache License, Version 2.0
 * Original Copyright: OpenSearch Contributors
 */
@SuppressWarnings("preview")
public final class OpenSslPanamaGcmCipher {

    public static final int AES_BLOCK_SIZE = 16;
    public static final int AES_256_KEY_SIZE = 32;

    public static final MethodHandle EVP_CIPHER_CTX_new;
    public static final MethodHandle EVP_CIPHER_CTX_free;
    public static final MethodHandle EVP_EncryptInit_ex;
    public static final MethodHandle EVP_EncryptUpdate;
    public static final MethodHandle EVP_EncryptFinal_ex;
    public static final MethodHandle EVP_DecryptInit_ex;
    public static final MethodHandle EVP_DecryptUpdate;
    public static final MethodHandle EVP_DecryptFinal_ex;
    public static final MethodHandle EVP_aes_256_gcm;
    public static final MethodHandle EVP_CIPHER_CTX_ctrl;

    private static final Linker LINKER = Linker.nativeLinker();
    private static final SymbolLookup LIBCRYPTO = loadLibcrypto();
    private static final int GCM_TAG_LEN = 16;

    private static SymbolLookup loadLibcrypto() {
        String os = System.getProperty("os.name").toLowerCase(Locale.ROOT);

        if (os.contains("mac")) {
            // Common Homebrew path for OpenSSL on macOS
            String[] macPaths = {
                    "/opt/homebrew/opt/openssl@3/lib/libcrypto.dylib",   // Apple Silicon (M1/M2)
                    "/usr/local/opt/openssl@3/lib/libcrypto.dylib"       // Intel Macs
            };

            for (String path : macPaths) {
                Path p = Path.of(path);
                if (Files.exists(p)) {
                    return SymbolLookup.libraryLookup(p, Arena.global());
                }
            }

            throw new RuntimeException("Could not find libcrypto.dylib in expected macOS locations.");
        } else if (os.contains("linux")) {
            try {
                // Try OpenSSL 3 first
                String[] linuxPaths = {
                        "/usr/lib/x86_64-linux-gnu/libcrypto.so.3", // OpenSSL 3
                        "/lib64/libcrypto.so.3",     // OpenSSL 3
                        "/lib64/libcrypto.so.1.1",   // OpenSSL 1.1 fallback
                        "/lib64/libcrypto.so.10",    // Legacy systems
                        "/lib64/libcrypto.so",       // Generic symlink
                        "/lib/libcrypto.so.3",
                        "/lib/libcrypto.so"};

                for (String path : linuxPaths) {
                    Path p = Path.of(path);
                    if (Files.exists(p)) {
                        return SymbolLookup.libraryLookup(p, Arena.global());
                    }
                }

                throw new RuntimeException("Could not find libcrypto in known Linux paths.");
            } catch (Exception e) {
                throw new RuntimeException("Failed to load libcrypto", e);
            }
        } else {
            throw new UnsupportedOperationException("Unsupported OS: " + os);
        }
    }

    /**
     * Custom exception for OpenSSL-related errors
     */
    public static class OpenSslException extends RuntimeException {
        public OpenSslException(String message) {
            super(message);
        }

        public OpenSslException(String message, Throwable cause) {
            super(message, cause);
        }
    }

    static {
        try {
            EVP_CIPHER_CTX_new = LINKER
                    .downcallHandle(LIBCRYPTO.find("EVP_CIPHER_CTX_new").orElseThrow(), FunctionDescriptor.of(ValueLayout.ADDRESS));

            EVP_CIPHER_CTX_free = LINKER
                    .downcallHandle(LIBCRYPTO.find("EVP_CIPHER_CTX_free").orElseThrow(), FunctionDescriptor.ofVoid(ValueLayout.ADDRESS));

            EVP_EncryptInit_ex = LINKER
                    .downcallHandle(
                            LIBCRYPTO.find("EVP_EncryptInit_ex").orElseThrow(),
                            FunctionDescriptor
                                    .of(
                                            ValueLayout.JAVA_INT,
                                            ValueLayout.ADDRESS,
                                            ValueLayout.ADDRESS,
                                            ValueLayout.ADDRESS,
                                            ValueLayout.ADDRESS,
                                            ValueLayout.ADDRESS
                                    )
                    );

            EVP_EncryptUpdate = LINKER
                    .downcallHandle(
                            LIBCRYPTO.find("EVP_EncryptUpdate").orElseThrow(),
                            FunctionDescriptor
                                    .of(
                                            ValueLayout.JAVA_INT,
                                            ValueLayout.ADDRESS, // ctx
                                            ValueLayout.ADDRESS, // out
                                            ValueLayout.ADDRESS, // outLen
                                            ValueLayout.ADDRESS, // in
                                            ValueLayout.JAVA_INT // inLen
                                    )
                    );

            EVP_EncryptFinal_ex = LINKER
                    .downcallHandle(
                            LIBCRYPTO.find("EVP_EncryptFinal_ex").orElseThrow(),
                            FunctionDescriptor
                                    .of(
                                            ValueLayout.JAVA_INT,
                                            ValueLayout.ADDRESS, // ctx
                                            ValueLayout.ADDRESS, // out
                                            ValueLayout.ADDRESS // outLen
                                    )
                    );


            EVP_DecryptInit_ex = LINKER
                    .downcallHandle(
                            LIBCRYPTO.find("EVP_DecryptInit_ex").orElseThrow(),
                            FunctionDescriptor
                                    .of(
                                            ValueLayout.JAVA_INT,
                                            ValueLayout.ADDRESS,
                                            ValueLayout.ADDRESS,
                                            ValueLayout.ADDRESS,
                                            ValueLayout.ADDRESS,
                                            ValueLayout.ADDRESS
                                    )
                    );

            EVP_DecryptUpdate = LINKER
                    .downcallHandle(
                            LIBCRYPTO.find("EVP_DecryptUpdate").orElseThrow(),
                            FunctionDescriptor
                                    .of(
                                            ValueLayout.JAVA_INT,
                                            ValueLayout.ADDRESS, // ctx
                                            ValueLayout.ADDRESS, // out
                                            ValueLayout.ADDRESS, // outLen
                                            ValueLayout.ADDRESS, // in
                                            ValueLayout.JAVA_INT // inLen
                                    )
                    );

            EVP_DecryptFinal_ex = LINKER
                    .downcallHandle(
                            LIBCRYPTO.find("EVP_DecryptFinal_ex").orElseThrow(),
                            FunctionDescriptor
                                    .of(
                                            ValueLayout.JAVA_INT,
                                            ValueLayout.ADDRESS, // ctx
                                            ValueLayout.ADDRESS, // out
                                            ValueLayout.ADDRESS // outLen
                                    )
                    );

            //int EVP_CIPHER_CTX_ctrl(EVP_CIPHER_CTX *ctx, int type, int arg, void *ptr);
            EVP_CIPHER_CTX_ctrl = LINKER
                    .downcallHandle(
                            LIBCRYPTO.find("EVP_CIPHER_CTX_ctrl").orElseThrow(),
                            FunctionDescriptor
                                    .of(
                                            ValueLayout.JAVA_INT,
                                            ValueLayout.ADDRESS, // ctx
                                            ValueLayout.JAVA_INT, // type
                                            ValueLayout.JAVA_INT, // arg
                                            ValueLayout.ADDRESS // ptr
                                    )
                    );

            EVP_aes_256_gcm = LINKER
                    .downcallHandle(LIBCRYPTO.find("EVP_aes_256_gcm").orElseThrow(), FunctionDescriptor.of(ValueLayout.ADDRESS));

        } catch (Throwable t) {
            throw new OpenSslException("Failed to initialize OpenSSL method handles via Panama", t);
        }
    }

    public static byte[] encryptOneShot(byte[] key, byte[] iv, byte[] input, int inputLen) throws Throwable {
        if (key == null || key.length != AES_256_KEY_SIZE) {
            throw new IllegalArgumentException("Invalid key length: expected " + AES_256_KEY_SIZE + " bytes");
        }
        if (iv == null || iv.length != 12) {
            throw new IllegalArgumentException("Invalid IV length: expected " + AES_BLOCK_SIZE + " bytes");
        }
        if (input == null || input.length == 0) {
            throw new IllegalArgumentException("Input cannot be null or empty");
        }

        try (Arena arena = Arena.ofConfined()) {
            MemorySegment ctx = (MemorySegment) EVP_CIPHER_CTX_new.invoke();
            if (ctx.address() == 0) {
                throw new OpenSslException("EVP_CIPHER_CTX_new failed");
            }

            try {
                MemorySegment cipher = (MemorySegment) EVP_aes_256_gcm.invoke();
                if (cipher.address() == 0) {
                    throw new OpenSslException("EVP_aes_256_gcm failed");
                }

                MemorySegment keySeg = arena.allocateArray(ValueLayout.JAVA_BYTE, key);
                MemorySegment ivSeg = arena.allocateArray(ValueLayout.JAVA_BYTE, iv);

                int rc = (int) EVP_EncryptInit_ex.invoke(ctx, cipher, MemorySegment.NULL, keySeg, ivSeg);
                if (rc != 1) {
                    throw new OpenSslException("EVP_EncryptInit_ex failed");
                }

                MemorySegment inSeg = arena.allocateArray(ValueLayout.JAVA_BYTE, input);
                MemorySegment outSeg = arena.allocate(inputLen + AES_BLOCK_SIZE);
                MemorySegment outLen = arena.allocate(ValueLayout.JAVA_INT);

                rc = (int) EVP_EncryptUpdate.invoke(ctx, outSeg, outLen, inSeg, inputLen);
                if (rc != 1) {
                    throw new OpenSslException("EVP_EncryptUpdate failed");
                }

                int bytesWritten = outLen.get(ValueLayout.JAVA_INT, 0);

                rc = (int) EVP_EncryptFinal_ex.invoke(ctx, outSeg, outLen);
                if (rc != 1) {
                    throw new OpenSslException("EVP_EncryptFinal_ex failed");
                }

                MemorySegment tagSeg = arena.allocate(GCM_TAG_LEN);
                rc = (int) EVP_CIPHER_CTX_ctrl.invoke(ctx, 16, GCM_TAG_LEN, tagSeg);
                if (rc != 1) {
                    throw new OpenSslException("EVP_CIPHER_CTX_ctrl failed");
                }

                //int EVP_CIPHER_CTX_ctrl(EVP_CIPHER_CTX *ctx, int type, int arg, void *ptr);
                //EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, outbuf);
                byte[] tag = tagSeg.asSlice(0, GCM_TAG_LEN).toArray(ValueLayout.JAVA_BYTE);

                byte[] dec = outSeg.asSlice(0, bytesWritten).toArray(ValueLayout.JAVA_BYTE);
                byte[] newArray = new byte[dec.length + tag.length];
                System.arraycopy(dec, 0, newArray, 0, dec.length);
                System.arraycopy(tag, 0, newArray, dec.length, tag.length);
                return newArray;


            } finally {
                EVP_CIPHER_CTX_free.invoke(ctx);
            }
        }
    }

    public static byte[] decryptOneShot(byte[] key, byte[] iv, byte[] input, int inputLen) throws Throwable {
        if (key == null || key.length != AES_256_KEY_SIZE) {
            throw new IllegalArgumentException("Invalid key length: expected " + AES_256_KEY_SIZE + " bytes");
        }
        if (iv == null || iv.length != 12) {
            throw new IllegalArgumentException("Invalid IV length: expected " + AES_BLOCK_SIZE + " bytes");
        }
        if (input == null || input.length == 0) {
            throw new IllegalArgumentException("Input cannot be null or empty");
        }

        try (Arena arena = Arena.ofConfined()) {
            MemorySegment ctx = (MemorySegment) EVP_CIPHER_CTX_new.invoke();
            if (ctx.address() == 0) {
                throw new OpenSslException("EVP_CIPHER_CTX_new failed");
            }

            try {
                MemorySegment cipher = (MemorySegment) EVP_aes_256_gcm.invoke();
                if (cipher.address() == 0) {
                    throw new OpenSslException("EVP_aes_256_gcm failed");
                }

                MemorySegment keySeg = arena.allocateArray(ValueLayout.JAVA_BYTE, key);
                MemorySegment ivSeg = arena.allocateArray(ValueLayout.JAVA_BYTE, iv);

                int rc = (int) EVP_DecryptInit_ex.invoke(ctx, cipher, MemorySegment.NULL, keySeg, ivSeg);
                if (rc != 1) {
                    throw new OpenSslException("EVP_EncryptInit_ex failed");
                }

                MemorySegment inSeg = arena.allocateArray(ValueLayout.JAVA_BYTE, Arrays.copyOf(input, inputLen - GCM_TAG_LEN));
                MemorySegment outSeg = arena.allocate(inputLen + AES_BLOCK_SIZE - GCM_TAG_LEN);
                MemorySegment outLen = arena.allocate(ValueLayout.JAVA_INT);

                rc = (int) EVP_DecryptUpdate.invoke(ctx, outSeg, outLen, inSeg, inputLen - GCM_TAG_LEN);
                if (rc != 1) {
                    throw new OpenSslException("EVP_DecryptUpdate failed");
                }

                int bytesWritten = outLen.get(ValueLayout.JAVA_INT, 0);

                MemorySegment tagSeg = arena.allocateArray(ValueLayout.JAVA_BYTE, Arrays.copyOfRange(input, inputLen - GCM_TAG_LEN, inputLen));
                rc = (int) EVP_CIPHER_CTX_ctrl.invoke(ctx, 17, GCM_TAG_LEN, tagSeg);
                if (rc != 1) {
                    throw new OpenSslException("EVP_CIPHER_CTX_ctrl failed");
                }

                rc = (int) EVP_DecryptFinal_ex.invoke(ctx, outSeg, outLen);
                if (rc != 1) {
                    throw new OpenSslException("EVP_DecryptFinal_ex failed");
                }

                return outSeg.asSlice(0, bytesWritten).toArray(ValueLayout.JAVA_BYTE);

            } finally {
                EVP_CIPHER_CTX_free.invoke(ctx);
            }
        }
    }


    private OpenSslPanamaGcmCipher() {
        // Utility class
    }
}
