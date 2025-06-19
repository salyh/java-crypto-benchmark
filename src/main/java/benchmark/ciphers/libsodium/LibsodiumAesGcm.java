package benchmark.ciphers.libsodium;

import java.lang.foreign.Arena;
import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.Linker;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.SymbolLookup;
import java.lang.foreign.ValueLayout;
import java.lang.invoke.MethodHandle;
import java.security.SecureRandom;
import java.util.Arrays;

public class LibsodiumAesGcm {

    private static final Linker LINKER = Linker.nativeLinker();
    private static final SymbolLookup LIBCRYPTO = LibsodiumLoader.loadLibcrypto();
    public static final MethodHandle crypto_aead_aes256gcm_encrypt;
    public static final MethodHandle crypto_aead_aes256gcm_decrypt;
    public static final MethodHandle sodium_init;
    private static final int KEY_SIZE = 32;
    private static final int NONCE_SIZE = 12;
    private static final int TAG_SIZE = 16;


    static {

        try {

            sodium_init = LINKER
                    .downcallHandle(LIBCRYPTO.find("sodium_init").orElseThrow(), FunctionDescriptor.of(
                            ValueLayout.JAVA_INT //return code
                    ));


            if ((int) sodium_init.invoke() < 0) {
                throw new LibsodiumException("sodium_init failed");
            }


        /*
                                           unsigned char *ciphertext,
                                           unsigned long long *ciphertext_len,
                                           const unsigned char *message,
                                           unsigned long long message_len,
                                           const unsigned char *ad, //aad
                                           unsigned long long adlen,
                                           const unsigned char *nsec, //NULL
                                           const unsigned char *nonce,
                                           const unsigned char *key)
         */

            crypto_aead_aes256gcm_encrypt = LINKER
                    .downcallHandle(LIBCRYPTO.find("crypto_aead_aes256gcm_encrypt").orElseThrow(), FunctionDescriptor.of(

                            ValueLayout.JAVA_INT, //return code
                            ValueLayout.ADDRESS,
                            ValueLayout.ADDRESS,
                            ValueLayout.ADDRESS,
                            ValueLayout.JAVA_LONG,
                            ValueLayout.ADDRESS,
                            ValueLayout.JAVA_LONG,
                            ValueLayout.ADDRESS,
                            ValueLayout.ADDRESS,
                            ValueLayout.ADDRESS


                    ));

        /*
                                           unsigned char *decrypted_message,
                                           unsigned long long *decrypted_message_len,
                                           unsigned char *nsec, //NULL
                                           const unsigned char *ciphertext,
                                           unsigned long long ciphertext_len,
                                           const unsigned char *ad,
                                           unsigned long long adlen,
                                           const unsigned char *nonce,
                                           const unsigned char *key)

         */

            crypto_aead_aes256gcm_decrypt = LINKER
                    .downcallHandle(LIBCRYPTO.find("crypto_aead_aes256gcm_decrypt").orElseThrow(), FunctionDescriptor.of(

                            ValueLayout.JAVA_INT, //return code
                            ValueLayout.ADDRESS,
                            ValueLayout.ADDRESS,
                            ValueLayout.ADDRESS,
                            ValueLayout.ADDRESS,
                            ValueLayout.JAVA_LONG,
                            ValueLayout.ADDRESS,
                            ValueLayout.JAVA_LONG,
                            ValueLayout.ADDRESS,
                            ValueLayout.ADDRESS


                    ));

        } catch (Throwable e) {
            throw new LibsodiumException(e);
        }

    }

    public static byte[] encryptOneShot(byte[] key, byte[] iv, byte[] input, int inputLen) {
        if (key == null || key.length != KEY_SIZE) {
            throw new IllegalArgumentException("Invalid key length: expected " + KEY_SIZE + " bytes");
        }
        if (iv == null || iv.length != NONCE_SIZE) {
            throw new IllegalArgumentException("Invalid IV length: expected " + NONCE_SIZE + " bytes");
        }
        if (input == null || input.length == 0) {
            throw new IllegalArgumentException("Input cannot be null or empty");
        }

        try (Arena arena = Arena.ofConfined()) {

            MemorySegment inSeg = arena.allocateFrom(ValueLayout.JAVA_BYTE, input);
            MemorySegment outSeg = arena.allocate(inputLen + TAG_SIZE);
            MemorySegment outLen = arena.allocate(ValueLayout.JAVA_LONG);
            MemorySegment keySeg = arena.allocateFrom(ValueLayout.JAVA_BYTE, key);
            MemorySegment ivSeg = arena.allocateFrom(ValueLayout.JAVA_BYTE, iv);

            int rc = (int) crypto_aead_aes256gcm_encrypt.invoke(
                    outSeg,
                    outLen,
                    inSeg,
                    (long) inputLen,
                    MemorySegment.NULL, //ad
                    0L, //ad len
                    MemorySegment.NULL, //nseg
                    ivSeg,
                    keySeg
            );

            if (rc != 0) {
                throw new LibsodiumException("crypto_aead_aes256gcm_encrypt failed");
            }


            return outSeg.asSlice(0, outLen.get(ValueLayout.JAVA_LONG, 0)).toArray(ValueLayout.JAVA_BYTE);
        } catch (Throwable e) {
            throw new LibsodiumException(e);
        }
    }

    public static byte[] decryptOneShot(byte[] key, byte[] iv, byte[] input, int inputLen) {
        if (key == null || key.length != KEY_SIZE) {
            throw new IllegalArgumentException("Invalid key length: expected " + KEY_SIZE + " bytes");
        }
        if (iv == null || iv.length != NONCE_SIZE) {
            throw new IllegalArgumentException("Invalid IV length: expected " + NONCE_SIZE + " bytes");
        }
        if (input == null || input.length == 0) {
            throw new IllegalArgumentException("Input cannot be null or empty");
        }

        try (Arena arena = Arena.ofConfined()) {

            MemorySegment inSeg = arena.allocateFrom(ValueLayout.JAVA_BYTE, input);
            MemorySegment outSeg = arena.allocate(inputLen);
            MemorySegment outLen = arena.allocate(ValueLayout.JAVA_LONG);
            MemorySegment keySeg = arena.allocateFrom(ValueLayout.JAVA_BYTE, key);
            MemorySegment ivSeg = arena.allocateFrom(ValueLayout.JAVA_BYTE, iv);

            int rc = (int) crypto_aead_aes256gcm_decrypt.invoke(
                    outSeg,
                    outLen,
                    MemorySegment.NULL, //nsec
                    inSeg,
                    (long) inputLen,
                    MemorySegment.NULL, //ad
                    0L, //ad len
                    ivSeg,
                    keySeg
            );

            if (rc != 0) {
                throw new LibsodiumException("crypto_aead_aes256gcm_decrypt failed");
            }

            return outSeg.asSlice(0, outLen.get(ValueLayout.JAVA_LONG, 0)).toArray(ValueLayout.JAVA_BYTE);
        } catch (Throwable e) {
            throw new LibsodiumException(e);
        }
    }

    private LibsodiumAesGcm() {
    }

    public static void main(String[] args) throws Throwable {
        byte[] nonce = new byte[12];
        new SecureRandom().nextBytes(nonce);

        byte[] key = new byte[32];
        new SecureRandom().nextBytes(key);

        byte[] plaintext = new byte[320];
        new SecureRandom().nextBytes(plaintext);

        byte[] ciphertext = encryptOneShot(key, nonce, plaintext, plaintext.length);
        byte[] decrypted = decryptOneShot(key, nonce, ciphertext, ciphertext.length);
        System.out.println(Arrays.equals(plaintext, decrypted));
    }
}
