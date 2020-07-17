package com.macasaet.fernet.property;

import com.pholser.junit.quickcheck.generator.GenerationStatus;
import com.pholser.junit.quickcheck.generator.Generator;
import com.pholser.junit.quickcheck.random.SourceOfRandomness;

public class CipherBytesGenerator extends Generator<byte[]> {

    public CipherBytesGenerator() {
        super(byte[].class);
    }

    public byte[] generate(SourceOfRandomness random, GenerationStatus status) {
        // max cipher text of 4mb in 16 byte chunks
        // TODO enforce this in the domain     
        final int numBlocks = random.nextInt(0, 4 * 1024 * 1024 / 16); 
        return random.nextBytes(numBlocks * 16);
    }

}