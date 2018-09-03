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
 * A {@link Validator} for payloads that represent objects as Strings (e.g. JSON or XML). This validator converts the
 * payload to a String then delegates to {@link #getStringTransformer()} to convert that String to an object. If the
 * deserialisation library you use already provides a way to convert binary into objects, then you can use
 * {@link Validator} directly instead.
 *
 * <p>Copyright &copy; 2017 Carlos Macasaet.</p>
 *
 * @author Carlos Macasaet
 * @param <T>
 *            The type of the payload. The Fernet token encodes the payload in binary. The type T should be a domain
 *            object or data transfer object representation of that data.
 */
public interface StringObjectValidator<T> extends Validator<T> {

    default Charset getCharset() {
        return charset;
    }

    /**
     * Override this to specify an alternative way to convert binary data into a String. The default implementation uses
     * the UTF-8 character set.
     *
     * @return a method for converting a byte array into a String
     */
    default Function<byte[], String> getStringCreator() {
        return bytes -> new String(bytes, getCharset());
    }

    @SuppressWarnings("PMD.LawOfDemeter")
    default Function<byte[], T> getTransformer() {
        return getStringCreator().andThen(getStringTransformer());
    }

    /**
     * Plug in your String deserialisation method here.
     *
     * @return a method for converting a String into an Object.
     */
    Function<String, T> getStringTransformer();

}