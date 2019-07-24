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

import static com.macasaet.fernet.Constants.charset;
import static com.macasaet.fernet.Constants.initializationVectorBytes;
import static com.macasaet.fernet.Constants.supportedVersion;

import java.security.SecureRandom;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.function.Supplier;

import javax.crypto.spec.IvParameterSpec;

public class TokenBuilder {

    private SecureRandom entropySource = new SecureRandom();
    private Clock clock = Clock.tickSeconds(ZoneOffset.UTC);
    private Supplier<Key> keySupplier;

    public TokenBuilder() {
    }

    protected TokenBuilder(final Clock clock, final SecureRandom entropySource, final Supplier<Key> keySupplier) {
        setClock(clock);
        setEntropySource(entropySource);
        setKeySupplier(keySupplier);
    }

    public TokenBuilder withEntropySource(final SecureRandom entropySource) {
        return new TokenBuilder(this.clock, entropySource, this.keySupplier);
    }

    public TokenBuilder withClock(final Clock clock) {
        return new TokenBuilder(clock, this.entropySource, this.keySupplier);
    }

    public TokenBuilder withKeySupplier(final Supplier<Key> keySupplier) {
        return new TokenBuilder(this.clock, this.entropySource, keySupplier);
    }

    public TokenBuilder withKey(final Key key) {
        return withKeySupplier(() -> key);
    }

    public Token build(final byte[] plainBytes) {
        final Instant timestamp = Instant.now(getClock());
        final IvParameterSpec initializationVector = generateInitializationVector();
        final Key key = getKeySupplier().get();
        final byte[] cipherText = key.encrypt(plainBytes, initializationVector);
        final byte[] hmac = key.sign(supportedVersion, timestamp, initializationVector, cipherText);
        return new Token(supportedVersion, timestamp, initializationVector, cipherText, hmac);
    }

    public Token build(final String plainText) {
        return build(plainText.getBytes(charset));
    }

    protected IvParameterSpec generateInitializationVector() {
        return new IvParameterSpec(generateInitializationVectorBytes());
    }

    protected byte[] generateInitializationVectorBytes() {
        final byte[] retval = new byte[initializationVectorBytes];
        getEntropySource().nextBytes(retval);
        return retval;
    }

    protected SecureRandom getEntropySource() {
        return entropySource;
    }

    protected void setEntropySource(SecureRandom entropySource) {
        this.entropySource = entropySource;
    }

    protected Supplier<Key> getKeySupplier() {
        if (keySupplier == null) {
            throw new IllegalStateException("A Fernet key supplier must be provided.");
        }
        return keySupplier;
    }

    protected void setKeySupplier(final Supplier<Key> keySupplier) {
        this.keySupplier = keySupplier;
    }

    protected Clock getClock() {
        return clock;
    }

    protected void setClock(Clock clock) {
        this.clock = clock;
    }

}