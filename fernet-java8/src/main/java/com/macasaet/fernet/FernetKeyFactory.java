/**
   Copyright 2020 Carlos Macasaet

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       https://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
 */
package com.macasaet.fernet;

import static com.macasaet.fernet.Constants.encryptionKeyBytes;
import static com.macasaet.fernet.Constants.signingKeyBytes;

import java.security.SecureRandom;
import java.util.Objects;

/**
 * A utility for generating new unique Fernet keys.
 *
 * <p>Copyright &copy; 2020 Carlos Macasaet.</p>
 *
 * @author Carlos Macasaet
 */
public class FernetKeyFactory {

    private final SecureRandom random;

    /**
     * Create a new factory using the system's default source of entropy.
     */
    public FernetKeyFactory() {
        this(new SecureRandom());
    }

    /**
     * Create a new factory with a custom entropy source.
     *
     * @param random a custom entropy source, cannot be null.
     */
    public FernetKeyFactory(final SecureRandom random) {
        Objects.requireNonNull(random);
        this.random = random;
    }

    /**
     * @return a randomly-generated Fernet key
     */
    @SuppressWarnings("PMD.LawOfDemeter")
    public Key generateKey() {
        final SecureRandom random = getRandom();
        final byte[] signingKey = new byte[signingKeyBytes];
        random.nextBytes(signingKey);
        final byte[] encryptionKey = new byte[encryptionKeyBytes];
        random.nextBytes(encryptionKey);
        return new Key(signingKey, encryptionKey);
    }

    protected SecureRandom getRandom() {
        return random;
    }

}