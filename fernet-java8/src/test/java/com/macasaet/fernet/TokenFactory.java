/**
   Copyright 2019 Carlos Macasaet

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
 */
package com.macasaet.fernet;

import static com.macasaet.fernet.Constants.initializationVectorBytes;
import static com.macasaet.fernet.Constants.supportedVersion;

import java.security.SecureRandom;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.function.Function;
import java.util.function.Supplier;

import javax.crypto.spec.IvParameterSpec;

public class TokenFactory<T> {

    private final Clock clock;
    private final SecureRandom entropySource;
    private final Supplier<Key> keySupplier;
    private final Function<T, byte[]> serialiser;

    public TokenFactory(final Function<T, byte[]> serialiser, final Supplier<Key> keySupplier) {
        this(Clock.tickSeconds(ZoneOffset.UTC), new SecureRandom(), serialiser, keySupplier);
    }

    public TokenFactory(final Clock clock, final SecureRandom entropySource, final Function<T, byte[]> transformer,
            final Supplier<Key> keySupplier) {
        if (clock == null) {
            throw new IllegalArgumentException("clock must be provided");
        }
        if (entropySource == null) {
            throw new IllegalArgumentException("entropySource must be provided");
        }
        if (transformer == null) {
            throw new IllegalArgumentException("serialiser must be provided");
        }
        if (keySupplier == null) {
            throw new IllegalArgumentException("keySupplier must be provided");
        }
        this.clock = clock;
        this.entropySource = entropySource;
        this.serialiser = transformer;
        this.keySupplier = keySupplier;
    }

    public Token generateToken(final T item) {
        final Instant timestamp = getClock().instant();
        final IvParameterSpec initializationVector = generateInitializationVector();
        final Key key = getKeySupplier().get();
        final byte[] cipherText = key.encrypt(getSerialiser().apply(item), initializationVector);
        final byte[] hmac = key.sign(supportedVersion, timestamp, initializationVector, cipherText);
        return new Token(supportedVersion, timestamp, initializationVector, cipherText, hmac);
    }

    protected IvParameterSpec generateInitializationVector() {
        final byte[] bytes = new byte[initializationVectorBytes];
        getEntropySource().nextBytes(bytes);
        return new IvParameterSpec(bytes);
    }

    protected Clock getClock() {
        return clock;
    }

    protected SecureRandom getEntropySource() {
        return entropySource;
    }

    protected Supplier<Key> getKeySupplier() {
        return keySupplier;
    }

    protected Function<T, byte[]> getSerialiser() {
        return serialiser;
    }

}