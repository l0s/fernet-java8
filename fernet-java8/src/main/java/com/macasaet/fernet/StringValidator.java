/**
   Copyright 2017 Carlos Macasaet

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

import java.nio.charset.Charset;
import java.util.function.Function;

/**
 * A {@link Validator} for String payloads. This is useful if your payload contains unique identifiers like user names.
 * If the payload is a structured String like JSON or XML, use {@link Validator} or {@link StringValidator} instead.
 *
 * <p>Copyright &copy; 2017 Carlos Macasaet.</p>
 *
 * @author Carlos Macasaet
 */
public interface StringValidator extends Validator<String> {

    default Charset getCharset() {
        return charset;
    }

    default Function<byte[], String> getTransformer() {
        return bytes -> new String(bytes, getCharset());
    }

}