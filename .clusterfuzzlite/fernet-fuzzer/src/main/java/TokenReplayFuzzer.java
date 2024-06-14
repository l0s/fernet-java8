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
import java.time.Instant;
import java.time.ZoneId;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.UUID;
import javax.crypto.spec.IvParameterSpec;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.code_intelligence.jazzer.api.FuzzerSecurityIssueHigh;
import com.code_intelligence.jazzer.api.FuzzerSecurityIssueMedium;
import com.macasaet.fernet.Key;
import com.macasaet.fernet.Token;
import com.macasaet.fernet.TokenValidationException;
import com.macasaet.fernet.Validator;

/**
 * This fuzzer simulates a replay attack
 */
public class TokenReplayFuzzer {

    /**
     * Freeze time for the fuzzer. In practice, the clock will return a different instant every second.
     */
    static Clock clock = Clock.fixed(Instant.ofEpochSecond(581182474), ZoneId.of("UTC"));
    /*
     * Run each fuzz input against the same key. Note that in practice, the key is likely rotated on a regular basis.
     */
    final static Key key = new Key("UrNImCIJQuYODgrBU5NgH5rpTc7l52IS5ELuhwF4RHU=");
    final static Validator<UUID> validator = new UuidValidator(clock) {

        public Clock getClock() {
            return clock;
        }
    };
    final static Utility utility = new Utility();

    public static void fuzzerTestOneInput(final FuzzedDataProvider data) {
        // retrieve a valid token from the server
        final var version = (byte) 0x80;
        final var timestamp = clock.instant();
        final var initializationVector = new IvParameterSpec(Base64.getUrlDecoder().decode("7x-FMghmHjn-6lVUKCsN-A=="));
        final var id = UUID.fromString("5c8293ac-6c70-4be0-823b-6ec391fc164b");
        final var idBytes = utility.toBytes(id);
        final var cipherText = key.encrypt(idBytes, initializationVector);
        final var signature = key.sign(version, timestamp, initializationVector, cipherText);
        final var validToken = new Token(version, timestamp, initializationVector, cipherText, signature) {
        };
        validator.validateAndDecrypt(key, validToken);

        // fast-forward time
        clock = Clock.fixed(clock.instant().plus(4, ChronoUnit.HOURS), ZoneId.of("UTC"));

        // replay the expired token
        final var forgedTimestamp = timestamp.plus(4, ChronoUnit.HOURS).plusSeconds(data.consumeLong(-60, 60));
        final var forgedSignature = utility.consumeBytes(data, 32);
        final var forgedToken = new Token(version, forgedTimestamp, initializationVector, cipherText, forgedSignature) {
        };

        try {
            final var forgedId = validator.validateAndDecrypt(key, forgedToken);
            if (forgedId.equals(id)) {
                throw new FuzzerSecurityIssueHigh("Fuzz input replayed a token");
            }
            throw new FuzzerSecurityIssueMedium("Fuzz input forged a signature with a different timestamp");
        } catch (final TokenValidationException ignored) {
        }
    }

}
