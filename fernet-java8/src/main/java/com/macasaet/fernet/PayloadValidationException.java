/**
   Copyright 2018 Carlos Macasaet

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

/**
 * This exception indicates that a Fernet token is valid, but the payload inside fails business logic validation.
 *
 * <p>Copyright &copy; 2018 Carlos Macasaet.</p>
 *
 * @author Carlos Macasaet
 */
public class PayloadValidationException extends TokenValidationException {

    private static final long serialVersionUID = -2067765218609208844L;

    public PayloadValidationException(final String message) {
        super(message);
    }

    public PayloadValidationException(final Throwable cause) {
        super(cause.getMessage(), cause);
    }

    public PayloadValidationException(final String message, final Throwable cause) {
        super(message, cause);
    }

}