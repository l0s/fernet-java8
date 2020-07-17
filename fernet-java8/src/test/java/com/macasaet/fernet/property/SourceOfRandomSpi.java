package com.macasaet.fernet.property;

import java.security.SecureRandomSpi;

import com.pholser.junit.quickcheck.random.SourceOfRandomness;

public class SourceOfRandomSpi extends SecureRandomSpi {

    private static final long serialVersionUID = 8302265772076050266L;

    private final SourceOfRandomness source;

    public SourceOfRandomSpi(final SourceOfRandomness source) {
        this.source = source;
    }

    protected void engineSetSeed(byte[] seed) {
        throw new UnsupportedOperationException();
    }

    protected void engineNextBytes(byte[] bytes) {
        source.nextBytes(bytes);
    }

    protected byte[] engineGenerateSeed(int numBytes) {
        return source.nextBytes(numBytes);
    }

}
