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
import javax.crypto.BadPaddingException;
import javax.crypto.spec.IvParameterSpec;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.code_intelligence.jazzer.api.FuzzerSecurityIssueHigh;
import com.macasaet.fernet.Key;
import com.macasaet.fernet.Token;
import com.macasaet.fernet.TokenValidationException;
import com.macasaet.fernet.Validator;

/**
 * This fuzzer simulates an attacker who does not have access to create a valid token (e.g. no login to the system)
 * attempting to craft a malicious token that does not rely on knowledge of the private signing or encryption keys.
 */
public class TokenDecryptFuzzer {

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
        final var initializationVector = new IvParameterSpec(utility.consumeBytes(data, 16));
        final var cipherText = utility.consumeBytes(data, 32); // random payload the size of an encrypted UUID
        final var signature = utility.consumeBytes(data, 32); // random signature of the right size
        final var timestamp = clock.instant().plus(Duration.ofSeconds(data.consumeLong(-60, 60)));
        // generate the shape of a valid token without knowing the encryption or signing key
        final var token = new Token((byte) 0x80, timestamp, initializationVector, cipherText, signature) {
        };

        try {
            final var result = token.validateAndDecrypt(key, validator);
            throw new FuzzerSecurityIssueHigh("Random input passed validation and generated UUID: " + result.toString());
        } catch (final TokenValidationException tve) {
            if (tve.getCause() instanceof BadPaddingException) {
                throw new FuzzerSecurityIssueHigh("Random input forged signature: " + tve.getCause().getMessage(), tve.getCause());
            }
        }
    }



}
