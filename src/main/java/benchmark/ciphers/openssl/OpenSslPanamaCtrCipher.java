/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
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
import java.util.Locale;

/**
 * Based on the work of the OpenSearch project (kumargu)
 * Originally licensed under the Apache License, Version 2.0
 * Original Copyright: OpenSearch Contributors
 */
@SuppressWarnings("preview")
public final class OpenSslPanamaCtrCipher {

    public static final int AES_BLOCK_SIZE = 16;
    public static final int AES_256_KEY_SIZE = 32;

    public static final MethodHandle EVP_CIPHER_CTX_new;
    public static final MethodHandle EVP_CIPHER_CTX_free;
    public static final MethodHandle EVP_EncryptInit_ex;
    public static final MethodHandle EVP_EncryptUpdate;
    public static final MethodHandle EVP_aes_256_ctr;

    private static final Linker LINKER = Linker.nativeLinker();
    private static final SymbolLookup LIBCRYPTO = loadLibcrypto();

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

            EVP_aes_256_ctr = LINKER
                    .downcallHandle(LIBCRYPTO.find("EVP_aes_256_ctr").orElseThrow(), FunctionDescriptor.of(ValueLayout.ADDRESS));

        } catch (Throwable t) {
            throw new OpenSslException("Failed to initialize OpenSSL method handles via Panama", t);
        }
    }

    public static byte[] encryptOneShot(byte[] key, byte[] iv, byte[] input, int inputLen) throws Throwable {
        if (key == null || key.length != AES_256_KEY_SIZE) {
            throw new IllegalArgumentException("Invalid key length: expected " + AES_256_KEY_SIZE + " bytes");
        }
        if (iv == null || iv.length != AES_BLOCK_SIZE) {
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
                MemorySegment cipher = (MemorySegment) EVP_aes_256_ctr.invoke();
                if (cipher.address() == 0) {
                    throw new OpenSslException("EVP_aes_256_ctr failed");
                }

                MemorySegment keySeg = arena.allocateFrom(ValueLayout.JAVA_BYTE, key);
                MemorySegment ivSeg = arena.allocateFrom(ValueLayout.JAVA_BYTE, iv);

                int rc = (int) EVP_EncryptInit_ex.invoke(ctx, cipher, MemorySegment.NULL, keySeg, ivSeg);
                if (rc != 1) {
                    throw new OpenSslException("EVP_EncryptInit_ex failed");
                }

                MemorySegment inSeg = arena.allocateFrom(ValueLayout.JAVA_BYTE, input);
                MemorySegment outSeg = arena.allocate(inputLen + AES_BLOCK_SIZE);
                MemorySegment outLen = arena.allocate(ValueLayout.JAVA_INT);

                rc = (int) EVP_EncryptUpdate.invoke(ctx, outSeg, outLen, inSeg, inputLen);
                if (rc != 1) {
                    throw new OpenSslException("EVP_EncryptUpdate failed");
                }

                int bytesWritten = outLen.get(ValueLayout.JAVA_INT, 0);
                return outSeg.asSlice(0, bytesWritten).toArray(ValueLayout.JAVA_BYTE);
            } finally {
                EVP_CIPHER_CTX_free.invoke(ctx);
            }
        }
    }

    public static byte[] decryptOneShot(byte[] key, byte[] iv, byte[] input, int inputLen) throws Throwable {
        if (key == null || key.length != AES_256_KEY_SIZE) {
            throw new IllegalArgumentException("Invalid key length: expected " + AES_256_KEY_SIZE + " bytes");
        }
        if (iv == null || iv.length != AES_BLOCK_SIZE) {
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
                MemorySegment cipher = (MemorySegment) EVP_aes_256_ctr.invoke();
                if (cipher.address() == 0) {
                    throw new OpenSslException("EVP_aes_256_ctr failed");
                }

                MemorySegment keySeg = arena.allocateFrom(ValueLayout.JAVA_BYTE, key);
                MemorySegment ivSeg = arena.allocateFrom(ValueLayout.JAVA_BYTE, iv);

                int rc = (int) EVP_EncryptInit_ex.invoke(ctx, cipher, MemorySegment.NULL, keySeg, ivSeg);
                if (rc != 1) {
                    throw new OpenSslException("EVP_EncryptInit_ex failed");
                }

                MemorySegment inSeg = arena.allocateFrom(ValueLayout.JAVA_BYTE, input);
                MemorySegment outSeg = arena.allocate(inputLen + AES_BLOCK_SIZE);
                MemorySegment outLen = arena.allocate(ValueLayout.JAVA_INT);

                rc = (int) EVP_EncryptUpdate.invoke(ctx, outSeg, outLen, inSeg, inputLen);
                if (rc != 1) {
                    throw new OpenSslException("EVP_EncryptUpdate failed during decryption");
                }

                int bytesWritten = outLen.get(ValueLayout.JAVA_INT, 0);
                return outSeg.asSlice(0, bytesWritten).toArray(ValueLayout.JAVA_BYTE);
            } finally {
                EVP_CIPHER_CTX_free.invoke(ctx);
            }
        }
    }


    private OpenSslPanamaCtrCipher() {
        // Utility class
    }
}
