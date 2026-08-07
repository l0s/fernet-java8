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
import java.util.UUID;
import java.util.function.Function;
import java.util.function.Predicate;

import com.macasaet.fernet.Validator;

class UuidValidator implements Validator<UUID> {

    private final Clock clock;

    public UuidValidator(final Clock clock) {
        this.clock = clock;
    }

    public Clock getClock() {
        return clock;
    }

    public Function<byte[], UUID> getTransformer() {
        return bytes -> {
            if (bytes.length != 16) {
                throw new IllegalArgumentException("Invalid UUID");
            }
            long mostSignificantBits = 0;
            for (int i = 0; i < 8; i++) {
                mostSignificantBits = (mostSignificantBits << 8) | (bytes[i] & 0xff);
            }

            long leastSignificantBits = 0;
            for (int i = 8; i < 16; i++) {
                leastSignificantBits = (leastSignificantBits << 8) | (bytes[i] & 0xff);
            }

            return new UUID(mostSignificantBits, leastSignificantBits);
        };
    }

    public Predicate<UUID> getObjectValidator() {
        return id -> id.version() == 4 && id.variant() == 2;
    }

}
