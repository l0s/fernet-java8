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
package com.macasaet.fernet.example.pb;

import static org.junit.Assert.assertEquals;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.TemporalAmount;
import java.util.Objects;
import java.util.UUID;
import java.util.function.Function;
import java.util.function.Predicate;

import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.BadRequestException;
import javax.ws.rs.POST;
import javax.ws.rs.PUT;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.Context;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.junit.MockitoJUnitRunner;

import com.google.protobuf.InvalidProtocolBufferException;
import com.macasaet.fernet.Key;
import com.macasaet.fernet.Token;
import com.macasaet.fernet.TokenValidationException;
import com.macasaet.fernet.Validator;
import com.macasaet.fernet.example.pb.Example.Session;
import com.macasaet.fernet.example.pb.Example.Session.Builder;

/**
 * This class demonstrates storing binary content in the Fernet token.
 *
 * <p>Copyright &copy; 2017 Carlos Macasaet.</p>
 *
 * @author Carlos Macasaet
 */
@RunWith(MockitoJUnitRunner.class)
public class ProtocolBuffersExampleIT {

    final Charset charset = StandardCharsets.UTF_8;
    final SecureRandom random = new SecureRandom();
    final Key key = Key.generateKey(random);

    private Validator<Session> validator = new Validator<Session>() {
        public Function<byte[], Session> getTransformer() {
            return bytes -> {
                try {
                    return Session.parseFrom(bytes);
                } catch (final InvalidProtocolBufferException e) {
                    throw new TokenValidationException("Invalid payload: " + e.getMessage(), e);
                }
            };
        }

        public Predicate<Session> getObjectValidator() {
            return session -> session.getRenewalCount() < 10;
        }

        public TemporalAmount getTimeToLive() {
            return Duration.ofMinutes(5);
        }
    };

    /**
     * Start a new session.
     *
     * @return a serialised Fernet token with a {@link Session} embedded in the payload
     */
    @POST
    @Path("/api/sessions")
    public String createSession(@Context final HttpServletResponse servletResponse) {
        final String sessionId = UUID.randomUUID().toString();
        final Builder builder = Session.newBuilder();
        builder.setSessionId(sessionId);
        builder.setRenewalCount(0);
        builder.setStartTime(Instant.now().getEpochSecond());
        servletResponse.addHeader("Location", "/api/sessions/" + sessionId);
        final Session session = builder.build();

        // persist session in server-side data store

        final Token token = Token.generate(random, key, session.toByteArray());
        return token.serialise();
    }

    /**
     * Renew a session 
     *
     * @param sessionId the existing session ID
     * @param tokenString a current valid Fernet token
     * @return a new Fernet token with the updated session state embedded
     */
    @PUT
    @Path("/api/sessions/{sessionId}/renewal")
    public String renew(@PathParam("sessionId") final String sessionId, final String tokenString,
            @Context final HttpServletResponse servletResponse) {
        final Token inputToken = Token.fromString(tokenString);
        final Session session = inputToken.validateAndDecrypt(key, validator);
        if (!Objects.equals(sessionId, session.getSessionId())) {
            throw new BadRequestException("SessionID mismatch.");
        }

        final Instant lastRenewed = Instant.ofEpochSecond(session.getLastRenewalTime());
        if (session.hasLastRenewalTime() && lastRenewed.isAfter(Instant.now().minus(Duration.ofMinutes(1)))) {
            // prevent denial-of-service
            // if token was renewed less than a minute ago, tell the client to back off
            servletResponse.addHeader("Retry-After", "60");
            // Too Many Requests: https://tools.ietf.org/html/rfc6585#section-4
            throw new WebApplicationException("Try again in a minute", 429);
        }

        // check session validity in server-side data store

        // The token and session are valid, now update the session
        final Builder builder = Session.newBuilder(session);
        builder.setRenewalCount(session.getRenewalCount() + 1);
        builder.setLastRenewalTime(Instant.now().getEpochSecond());
        final Session updatedSession = builder.build();

        // update session in server-side data store

        // store the updated session in a new Fernet token
        final Token retval = Token.generate(random, key, updatedSession.toByteArray());
        return retval.serialise();
    }

    @Captor
    ArgumentCaptor<String> locationHeaderCaptor;

    @Test
    public final void testRenewal() {
        // given
        final HttpServletResponse initialResponse = mock(HttpServletResponse.class);
        final String initialToken = createSession(initialResponse);
        verify(initialResponse).addHeader(eq("Location"), locationHeaderCaptor.capture());
        final String location = locationHeaderCaptor.getValue();
        final String sessionId = location.substring(location.lastIndexOf('/') + 1);

        // when
        final HttpServletResponse renewalResponse = mock(HttpServletResponse.class);
        final String subsequentToken = renew(sessionId, initialToken, renewalResponse);

        // then
        final Session result = Token.fromString(subsequentToken).validateAndDecrypt(key, validator);
        assertEquals(1, result.getRenewalCount());
        assertEquals(sessionId, result.getSessionId());
    }

}