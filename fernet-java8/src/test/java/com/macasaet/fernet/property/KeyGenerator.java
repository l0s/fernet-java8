package com.macasaet.fernet.property;

import java.security.SecureRandom;
import java.security.SecureRandomSpi;

import com.macasaet.fernet.Key;
import com.pholser.junit.quickcheck.generator.GenerationStatus;
import com.pholser.junit.quickcheck.generator.Generator;
import com.pholser.junit.quickcheck.random.SourceOfRandomness;

public class KeyGenerator extends Generator<Key> {

    public KeyGenerator() {
        super(Key.class);
    }

    public Key generate(SourceOfRandomness random, GenerationStatus status) {
        final SecureRandomSpi spi = new SourceOfRandomSpi(random);
        final SecureRandom secureRandom = new SecureRandom(spi ,null) {
            private static final long serialVersionUID = -8769820329345037169L;
        };
        return Key.generateKey(secureRandom);
    }

}
