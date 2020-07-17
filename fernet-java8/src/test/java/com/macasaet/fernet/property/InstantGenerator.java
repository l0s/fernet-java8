package com.macasaet.fernet.property;

import java.time.Instant;

import com.pholser.junit.quickcheck.generator.GenerationStatus;
import com.pholser.junit.quickcheck.generator.Generator;
import com.pholser.junit.quickcheck.random.SourceOfRandomness;

public class InstantGenerator extends Generator<Instant> {

    public InstantGenerator() {
        super(Instant.class);
    }

    public Instant generate(SourceOfRandomness random, GenerationStatus status) {
        final long epochSeconds = random.nextLong(Instant.MIN.getEpochSecond(), Instant.MAX.getEpochSecond());
        final long nanosecondAdjustment = random.nextLong();
        return Instant.ofEpochSecond(epochSeconds, nanosecondAdjustment);
    }

}
