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

import java.time.Clock;
import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.util.HashMap;
import java.util.Map;

/**
 * This class simulates client-side logic. We assume that the source code and any stored data is freely accessible. 
 *
 * <p>Copyright &copy; 2017 Carlos Macasaet.</p>
 *
 * @author Carlos Macasaet
 */
public class Client {

    private final DateTimeFormatter formatter = DateTimeFormatter.ISO_INSTANT;
    private final Clock clock;
    private final Server server;

    public Client(final Clock clock, final Server server) {
        this.clock = clock;
        this.server = server;
    }

    /**
     * This represents something like browser local storage, a cookie, or application state. It is easily compromised by
     * physical access to the customer's computer.
     */
    private Map<String, String> insecureStorage = new HashMap<>();

    /**
     * This represents a UI element that prompts the customer to provide sensitive information. It can either be a blank
     * form or pre-filled with obfuscated data.
     */
    public static class Form {
        public String notificationType;
        public String firstName;
        public String lastName;
        public String emailAddress;
        public boolean autofilled = false;
    }

    /**
     * This presents a form to the end user based on the state of the application. If the customer had previously filled
     * out a form, a pre-filled form will be presented.
     * 
     * @return either a blank or autofilled form
     */
    public Form renderForm() {
        if (insecureStorage.containsKey("secureEnvelope") && insecureStorage.containsKey("expirationDateTime")) {
            final String expirationDateTimeString = insecureStorage.get("expirationDateTime");
            final Instant expirationDateTime = Instant.from(formatter.parse(expirationDateTimeString));
            if (Instant.now(clock).isBefore(expirationDateTime)) {
                // a non-expired token is available, present a pre-filled form
                final Form autoFillForm = new Form();
                // present the obfuscated data from insecure storage
                autoFillForm.firstName = insecureStorage.get("firstName");
                autoFillForm.lastName = insecureStorage.get("lastName");
                autoFillForm.emailAddress = insecureStorage.get("emailAddress");
                autoFillForm.autofilled = true;
                return autoFillForm;
            }
            // we've cached the sensitive information, but the token is expired and unusable
            // clear the cache
            insecureStorage.clear();
        }
        // either there is no stored data or it is expired, so render a blank form
        return new Form();
    }

    /**
     * Submit the form data to the server.
     *
     * @param form a form filled-out by the customer or autofilled by the system
     * @throws Exception if the server cannot fulfill the request
     */
    public void submit(final Form form) throws Exception {
        if (form.autofilled) {
            final Response response = server.register(form.notificationType, insecureStorage.get("secureEnvelope"));
            // update the token and expiration timestamp
            insecureStorage.put("secureEnvelope", response.secureEnvelope);
            insecureStorage.put("expirationDateTime", response.expirationDateTime);
        } else {
            // save obfuscated data to insecure storage
            // substitute this with your own obfuscation rules
            insecureStorage.put("firstName", "******");
            insecureStorage.put("lastName", "******");
            insecureStorage.put("emailAddress", "****@******.***");
            final Response response = server.register(form.notificationType, form.firstName, form.lastName,
                    form.emailAddress);
            // save the token and expiration timestamp
            insecureStorage.put("secureEnvelope", response.secureEnvelope);
            insecureStorage.put("expirationDateTime", response.expirationDateTime);
        }
        // this example does not account for the scenario that the token expired after the form was presented but before
        // it was submitted
    }

}