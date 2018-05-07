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

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;

import org.junit.Test;

import com.macasaet.fernet.example.autofill.Client.Form;

/**
 * <p>In this example, a website presents a form that requires a user to provide personally-identifying information in
 * order to sign up for various types of notifications. In this scenario, the user may wish to register for multiple
 * notification types. In order to streamline subsequent registrations, we would like to auto-fill the form. However, if
 * the user's computer is compromised, we do not want to allow third-parties to glean the user's personal information.</p>
 * 
 * <p>In this example, the server embeds the user's personal information in a Fernet token. The client is responsible for
 * storing it.</p>
 *
 * <p>Copyright &copy; 2017 Carlos Macasaet.</p>
 *
 * @author Carlos Macasaet
 */
public class AutofillExampleIT {

    private Instant now = Instant.now();
    private Clock clock = new Clock() {

        public Clock withZone(ZoneId zone) {
            return this;
        }

        public Instant instant() {
            return now;
        }

        public ZoneId getZone() {
            return ZoneOffset.UTC;
        }
    };
    private final Server server = new Server(clock);
    private final Client client = new Client(clock, server);

    @Test
    public final void demo() throws Exception {
        // the first time the form is presented, all the information must be provided
        Form form = client.renderForm();
        assertFalse(form.autofilled);
        form.firstName = "Alice";
        form.lastName = "Dodgson";
        form.emailAddress = "alice@example.com";
        form.notificationType = "white rabbits";

        client.submit(form);
        now = now.plusSeconds(60);

        // the second time the form is presented, the fields are autofilled with obfuscated data
        form = client.renderForm();
        assertTrue(form.autofilled);
        assertNotEquals("alice@example.com", form.emailAddress);
        assertNotEquals("Dodgson", form.lastName);
        assertNotEquals("Alice", form.firstName);

        // the customer only needs to specify the notification type
        // personal information need not be provided again
        form.notificationType = "tea time";

        client.submit(form);

        // if the customer waits too long, the form will not be autofilled
        now = now.plus(Duration.ofDays(1).plusMinutes(1));

        form = client.renderForm();
        assertFalse(form.autofilled);
        assertNull(form.firstName);
        assertNull(form.lastName);
        assertNull(form.emailAddress);
    }

}