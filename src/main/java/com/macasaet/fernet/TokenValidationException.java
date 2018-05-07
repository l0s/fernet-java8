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

/**
 * This exception indicates that an operation (e.g. payload decryption) was
 * attempted on an invalid Fernet token.
 *
 * <p>Copyright &copy; 2017 Carlos Macasaet.</p>
 *
 * @author Carlos Macasaet
 */
public class TokenValidationException extends RuntimeException {

    private static final long serialVersionUID = 5175834607547919885L;

    public TokenValidationException(final String message) {
        super(message);
    }

    public TokenValidationException(final Throwable cause) {
        this(cause.getMessage(), cause);
    }

    public TokenValidationException(final String message, final Throwable cause) {
        super(message, cause);
    }

}