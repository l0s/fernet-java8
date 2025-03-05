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

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.util.UUID;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;

class Utility {

    /**
     * @param data     the fuzzing input source
     * @param numBytes the _exact_ number of bytes to consume
     * @return an array of exactly numBytes length
     */
    public byte[] consumeBytes(final FuzzedDataProvider data, final int numBytes) {
        var result = new byte[0];
        while (result.length < numBytes) {
            final var bytes = data.consumeBytes(numBytes - result.length);
            final var temp = new byte[result.length + bytes.length];
            System.arraycopy(result, 0, temp, 0, result.length);
            System.arraycopy(bytes, 0, temp, result.length, bytes.length);
            result = temp;
        }
        return result;
    }

    public byte[] toBytes(final UUID uuid) {
        try(var output = new ByteArrayOutputStream()) {
            try(var data = new DataOutputStream(output)) {
                data.writeLong(uuid.getMostSignificantBits());
                data.writeLong(uuid.getLeastSignificantBits());
                return output.toByteArray();
            }
        } catch (IOException e) {
            throw new RuntimeException(e.getMessage(), e);
        }
    }

}
