/*
   Copyright 2022 Carlos Macasaet

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

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.util.UUID;
import javax.crypto.spec.IvParameterSpec;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.code_intelligence.jazzer.api.FuzzerSecurityIssueHigh;
import com.macasaet.fernet.Key;
import com.macasaet.fernet.Token;
import com.macasaet.fernet.Validator;

/**
 * This fuzzer simulates an attacker who has access to the system and is attempting to exploit the token mechanism.
 */
public class TokenEncryptDecryptFuzzer {

    /**
     * Freeze time for the fuzzer. In practice, the clock will return a different instant every second.
     */
    final static Clock clock = Clock.fixed(Instant.ofEpochSecond(581182474), ZoneId.of("UTC"));
    /*
     * Run each fuzz input against the same key. Note that in practice, the key is likely rotated on a regular basis.
     */
    final static Key key = new Key("UrNImCIJQuYODgrBU5NgH5rpTc7l52IS5ELuhwF4RHU=");
    final static Validator<UUID> validator = new UuidValidator(clock);
    final static Utility utility = new Utility();

    public static void fuzzerTestOneInput(final FuzzedDataProvider data) {
        final var version = (byte) 0x80;
        final var timestamp = clock.instant().plus(Duration.ofSeconds(data.consumeLong(-60, 60)));
        final var initializationVector = new IvParameterSpec(utility.consumeBytes(data, 16));
        final var idBytes = utility.consumeBytes(data, 16);
        // copied from JDK
        idBytes[6] &= 0x0f;  /* clear version        */
        idBytes[6] |= 0x40;  /* set to version 4     */
        idBytes[8] &= 0x3f;  /* clear variant        */
        idBytes[8] |= 0x80;  /* set to IETF variant  */
        final var cipherText = key.encrypt(idBytes, initializationVector);
        final var signature = key.sign(version, timestamp, initializationVector, cipherText);

        final var token = new Token(version, timestamp, initializationVector, cipherText, signature) {
        };
        final var serialised = token.serialise();
        final var deserialised = Token.fromString(serialised);
        final var decrypted = deserialised.validateAndDecrypt(key, validator);
        if (!validator.getTransformer().apply(idBytes).equals(decrypted)) {
            throw new FuzzerSecurityIssueHigh("Encryption/decryption fault");
        }
    }

}
