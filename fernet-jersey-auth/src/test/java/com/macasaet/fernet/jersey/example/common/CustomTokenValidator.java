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
package com.macasaet.fernet.jersey.example.common;

import java.time.Duration;
import java.time.temporal.TemporalAmount;
import java.util.UUID;
import java.util.function.Function;
import java.util.function.Predicate;

import javax.inject.Inject;
import javax.inject.Singleton;

import com.macasaet.fernet.StringObjectValidator;

/**
 * This {@link com.macasaet.fernet.Validator Validator} assumes that the Fernet Token payload is a session. It obtains
 * a Session POJO from a datastore and validates that it is still valid.
 *
 * <p>Copyright &copy; 2018 Carlos Macasaet.</p>
 * @author Carlos Macasaet
 */
@Singleton
public class CustomTokenValidator implements StringObjectValidator<Session> {

    @Inject
    private SessionRepository sessionRepository;

    public Function<String, Session> getStringTransformer() {
        return string -> {
            final UUID id = UUID.fromString(string);
            return sessionRepository.findSession(id);
        };
    }

    public Predicate<Session> getObjectValidator() {
        return session -> {
            // This might be a valid Fernet Token, but the session may have been
            // revoked on the server side.
            return session != null && !session.isRevoked();
        };
    }

    public TemporalAmount getTimeToLive() {
        // token expiration matches session expiration
        return Duration.ofMinutes(30);
    }

}