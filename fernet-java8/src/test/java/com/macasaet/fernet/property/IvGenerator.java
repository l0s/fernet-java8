package com.macasaet.fernet.property;

import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.spec.IvParameterSpec;

import com.pholser.junit.quickcheck.generator.GenerationStatus;
import com.pholser.junit.quickcheck.generator.Generator;
import com.pholser.junit.quickcheck.random.SourceOfRandomness;

public class IvGenerator extends Generator<IvParameterSpec> {

    public IvGenerator() {
        super(IvParameterSpec.class);
    }

    public IvParameterSpec generate(SourceOfRandomness random, GenerationStatus status) {
        return new IvParameterSpec(random.nextBytes(16)) {

            public String toString() {
                final StringBuilder builder = new StringBuilder();
                builder.append("IvParameterSpec[");
                builder.append(Base64.getUrlEncoder().encodeToString(getIV()));
                builder.append(']');
                return builder.toString();
            }

            public int hashCode() {
                return Arrays.hashCode(getIV());
            }

            public boolean equals(final Object object) {
                if (object == null) {
                    return false;
                } else if (this == object) {
                    return true;
                }

                try {
                    final IvParameterSpec other = (IvParameterSpec) object;
                    return MessageDigest.isEqual(getIV(), other.getIV());
                } catch (final ClassCastException cce) {
                    return false;
                }
            }
        };
    }

}
