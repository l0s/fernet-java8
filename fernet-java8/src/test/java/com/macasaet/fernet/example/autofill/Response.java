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
package com.macasaet.fernet.example.autofill;

import com.macasaet.fernet.Token;

/**
 * This represents the response from the API. It may be stored in insecure client storage (e.g. cookie). It allows
 * the client to present a simplified interface so that the customer does not need to re-enter sensitive
 * information. If the customer's computer is stolen or compromised, the worst that can happen is that another
 * person can register the customer for other notification types (from which the customer can unsubscribe). However,
 * the customer's personal information cannot be viewed.
 *
 * <p>Copyright &copy; 2017 Carlos Macasaet.</p>
 *
 * @author Carlos Macasaet
 */
public class Response {

    /**
     * This contains encrypted sensitive information required for subsequent registration requests. If stolen, it
     * can only be used until {@link #expirationDateTime}. This is just the serialised version of a {@link Token}.
     * It is generated server-side and can only be decrypted server-side.
     */
    public String secureEnvelope;

    /**
     * This is an ISO-8601 timestamp that tells the client when {@link #secureEnvelope} will no longer be valid.
     * After that time, the client will need to solicit the sensitive information from the customer again.
     */
    public String expirationDateTime;

}