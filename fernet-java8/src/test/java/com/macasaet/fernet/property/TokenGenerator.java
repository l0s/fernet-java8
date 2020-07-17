package com.macasaet.fernet.property;

import java.security.SecureRandom;
import java.security.SecureRandomSpi;

import com.macasaet.fernet.Key;
import com.macasaet.fernet.Token;
import com.pholser.junit.quickcheck.generator.GenerationStatus;
import com.pholser.junit.quickcheck.generator.Generator;
import com.pholser.junit.quickcheck.random.SourceOfRandomness;

public class TokenGenerator extends Generator<Token> {

    private final Generator<Key> keyGenerator = new KeyGenerator();

    public TokenGenerator() {
        super(Token.class);
    }

    public Token generate(SourceOfRandomness random, GenerationStatus status) {
        final SecureRandomSpi spi = new SourceOfRandomSpi(random);
        final SecureRandom secureRandom = new SecureRandom(spi, null) {
            private static final long serialVersionUID = -8769820329345037169L;
        };
        final Key key = keyGenerator.generate(random, status);
        final int payloadSize = random.nextInt(4 * 1024 * 1024);
        return Token.generate(secureRandom, key, random.nextBytes(payloadSize));
    }

}
