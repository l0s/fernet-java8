package com.macasaet.fernet.example.pb;

import static org.junit.Assert.assertEquals;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.MockitoAnnotations.initMocks;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.TemporalAmount;
import java.util.Objects;
import java.util.Random;
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

import org.junit.Before;
import org.junit.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;

import com.google.protobuf.InvalidProtocolBufferException;
import com.macasaet.fernet.Key;
import com.macasaet.fernet.Token;
import com.macasaet.fernet.TokenValidationException;
import com.macasaet.fernet.Validator;
import com.macasaet.fernet.example.pb.Example.Session;
import com.macasaet.fernet.example.pb.Example.Session.Builder;

public class ProtocolBuffersExample {

    final Charset charset = StandardCharsets.UTF_8;
    final Random random = new SecureRandom();
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
        final Token token = Token.generate(random, key, session.toByteArray());
        return token.serialise();
    }

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

        final Builder builder = Session.newBuilder(session);
        builder.setRenewalCount(session.getRenewalCount() + 1);
        builder.setLastRenewalTime(Instant.now().getEpochSecond());
        final Session updatedSession = builder.build();
        final Token retval = Token.generate(random, key, updatedSession.toByteArray());
        return retval.serialise();
    }

    @Captor
    ArgumentCaptor<String> locationHeaderCaptor;

    @Before
    public void setUp() {
        initMocks(this);
    }

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