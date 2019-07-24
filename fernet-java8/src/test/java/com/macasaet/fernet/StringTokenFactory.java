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

import java.security.SecureRandom;
import java.time.Clock;
import java.util.function.Function;
import java.util.function.Supplier;


public class StringTokenFactory extends TokenFactory<String> {

    private static final Function<String, byte[]> transformer = string -> string.getBytes(charset);

    public StringTokenFactory(final Key key) {
        this(() -> key);
    }

    public StringTokenFactory(final Supplier<Key> keySupplier) {
        super(transformer, keySupplier);
    }

    public StringTokenFactory(final Clock clock, final SecureRandom entropySource, final Supplier<Key> keySupplier) {
        super(clock, entropySource, transformer, keySupplier);
    }

}