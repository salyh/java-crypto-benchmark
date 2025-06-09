# Java Cipher Benchmark

## Introduction

* JMH based
* Compares Libsodium AES GCM and XChaCha20-Poly1305 with JDK's AES GCM, AES CTR, and ChaCha20-Poly1305
* via Libsodium binding [Tuweni](https://github.com/consensys/tuweni)
* Easy to run and setup
* Easy to extend
* Next step: Integrate native OpenSSL implementations via [Apache Commons Crypto](https://commons.apache.org/proper/commons-crypto/)

## Run

```
mvn clean package
java -jar target/crypto-benchmark-1.0.0-benchmarks.jar.jar
```

## Results

Lower scores are better

```
# On Linux x86_64
# Linux ubuntu-32gb-nbg1-1 6.8.0-52-generic #53-Ubuntu SMP PREEMPT_DYNAMIC Sat Jan 11 00:06:25 UTC 2025 x86_64 x86_64 x86_64 GNU/Linux
# model name: AMD EPYC-Milan Processor
# 8 cores
# Libsodium 1.0.18 (via Tuweni JNA bindings)

# JDK 21.0.7, OpenJDK 64-Bit Server VM, 21.0.7+6-Ubuntu-0ubuntu124.04
Benchmark                           (algorithm)  Mode  Cnt    Score   Error  Units
CipherBenchmark.crypt             TuweniAES_GCM  avgt    5   34.246 ± 1.667  ms/op
CipherBenchmark.crypt  TuweniXCHACHA20_POLY1305  avgt    5   38.660 ± 1.563  ms/op
CipherBenchmark.crypt                   AES_GCM  avgt    5   22.252 ± 1.928  ms/op   ***
CipherBenchmark.crypt                   AES_CTR  avgt    5  127.886 ± 7.593  ms/op
CipherBenchmark.crypt         CHACHA20_POLY1305  avgt    5   98.759 ± 4.075  ms/op

# JDK 23, OpenJDK 64-Bit Server VM, 23+37-2369
Benchmark                           (algorithm)  Mode  Cnt    Score   Error  Units
CipherBenchmark.crypt             TuweniAES_GCM  avgt    5   34.419 ± 2.441  ms/op
CipherBenchmark.crypt  TuweniXCHACHA20_POLY1305  avgt    5   38.134 ± 2.285  ms/op
CipherBenchmark.crypt                   AES_GCM  avgt    5   17.546 ± 2.496  ms/op   ***
CipherBenchmark.crypt                   AES_CTR  avgt    5  124.806 ± 7.046  ms/op
CipherBenchmark.crypt         CHACHA20_POLY1305  avgt    5   97.280 ± 6.422  ms/op


# JDK 24.0.1, OpenJDK 64-Bit Server VM, 24.0.1+9-snap
Benchmark                           (algorithm)  Mode  Cnt   Score   Error  Units
CipherBenchmark.crypt             TuweniAES_GCM  avgt    5  34.388 ± 1.059  ms/op
CipherBenchmark.crypt  TuweniXCHACHA20_POLY1305  avgt    5  38.105 ± 1.807  ms/op
CipherBenchmark.crypt                   AES_GCM  avgt    5  17.645 ± 1.907  ms/op
CipherBenchmark.crypt                   AES_CTR  avgt    5   9.542 ± 0.724  ms/op   ***
CipherBenchmark.crypt         CHACHA20_POLY1305  avgt    5  98.207 ± 6.942  ms/op


# On Mac M1 Max, 10 cores
# -----------------------

# JDK 21.0.7, OpenJDK 64-Bit Server VM, 21.0.7+6-LTS
# Libsodium 1.0.20 (via Tuweni JNA bindings)
Benchmark                           (algorithm)  Mode  Cnt    Score    Error  Units
CipherBenchmark.crypt             TuweniAES_GCM  avgt    5   73,349 ±  2,973  ms/op
CipherBenchmark.crypt  TuweniXCHACHA20_POLY1305  avgt    5  130,381 ±  1,901  ms/op
CipherBenchmark.crypt                   AES_GCM  avgt    5   16,768 ±  0,302  ms/op
CipherBenchmark.crypt                   AES_CTR  avgt    5  108,846 ±  1,349  ms/op
CipherBenchmark.crypt         CHACHA20_POLY1305  avgt    5   78,008 ± 80,871  ms/op



# JDK 24.0.1, OpenJDK 64-Bit Server VM, 24.0.1+9
# Libsodium 1.0.20 (via Tuweni JNA bindings)
Benchmark                           (algorithm)  Mode  Cnt    Score    Error  Units
CipherBenchmark.crypt             TuweniAES_GCM  avgt    5   70,273 ±  1,979  ms/op
CipherBenchmark.crypt  TuweniXCHACHA20_POLY1305  avgt    5  131,739 ±  2,226  ms/op
CipherBenchmark.crypt                   AES_GCM  avgt    5   15,865 ±  0,092  ms/op
CipherBenchmark.crypt                   AES_CTR  avgt    5    9,862 ±  0,709  ms/op
CipherBenchmark.crypt         CHACHA20_POLY1305  avgt    5   77,411 ± 83,493  ms/op
```

### Conclusion

* Java AES CTR is slow on Java <= 23, but fast on Java 24
* Java AES GCM is fast on all JDKs, but Java AES CTR is twice as fast on Java 24
* If AES is not an option use Tuweni/Libsodium XCHACHA20_POLY1305 (on Linux two time slower than AES GCM)
* Do not use Java ChaCha20-Poly1305 or Tuweni/Libsodium AES GCM

### Recommendations

(We still need to check the native OpenSSL performance)
* Do not use AES CTR on Java <= 23
* If speed is important and you can omit authentication (or implement it otherwise) use CTR with Java 24
* If you can live with AES GCM limitations (see below) use it, if not use Tuweni/Libsodium XCHACHA20_POLY1305

### A warning on AES GCM

AES GCM is a beast and can be dangerous.

See https://soatok.blog/2020/05/13/why-aes-gcm-sucks/
See https://libsodium.gitbook.io/doc/secret-key_cryptography/aead/aes-256-gcm

Most important:
* Nonce reuse breaks the security
* Limitations on the maximum amount of data that can be encrypted with the same key/nonce
* Short Nonces
