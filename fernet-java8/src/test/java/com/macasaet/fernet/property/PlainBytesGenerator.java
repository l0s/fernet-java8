package com.macasaet.fernet.property;

import com.pholser.junit.quickcheck.generator.GenerationStatus;
import com.pholser.junit.quickcheck.generator.Generator;
import com.pholser.junit.quickcheck.random.SourceOfRandomness;

public class PlainBytesGenerator extends Generator<byte[]> {

    public PlainBytesGenerator() {
        super(byte[].class);
    }

    public byte[] generate(SourceOfRandomness random, GenerationStatus status) {
        // max payload of 4MB
        // TODO document this
        final int size = random.nextInt(4 * 1024 * 1024);
        return random.nextBytes(size);
    }

}