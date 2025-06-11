package benchmark.algos;

import java.util.Arrays;

/**
 * DO NOT USE THIS CLASS IN PRODUCTION!
 */
public class NullAlgorithm implements CryptoAlgorithm {

    @Override
    public void init() throws Exception {

    }

    @Override
    public void reInit() throws Exception {

    }

    @Override
    public byte[] encrypt(byte[] data, int inputLen, boolean last) throws Exception {
        return Arrays.copyOf(data, inputLen);
    }

    @Override
    public byte[] decrypt(byte[] data, int inputLen, boolean last) throws Exception {
        return Arrays.copyOf(data, inputLen);
    }

    @Override
    public int tagLen() {
        return 0;
    }

}
