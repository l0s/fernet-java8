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
package com.macasaet.fernet.jersey.example.secretinjection;

import static org.glassfish.jersey.test.TestProperties.CONTAINER_PORT;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.UUID;

import javax.crypto.spec.IvParameterSpec;
import javax.ws.rs.ForbiddenException;
import javax.ws.rs.NotAuthorizedException;
import javax.ws.rs.client.Entity;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import org.glassfish.jersey.test.JerseyTest;
import org.hamcrest.CustomTypeSafeMatcher;
import org.hamcrest.Matcher;
import org.junit.Test;
import org.slf4j.bridge.SLF4JBridgeHandler;

import com.macasaet.fernet.Key;
import com.macasaet.fernet.Token;
import com.macasaet.fernet.jersey.example.common.LoginRequest;
import com.macasaet.fernet.jersey.example.common.Session;

public class SecretInjectionIT extends JerseyTest {

    private static final Matcher<NotAuthorizedException> notAuthorisedMatcher = new CustomTypeSafeMatcher<NotAuthorizedException>("NotAuthorizedException") {
        protected boolean matchesSafely(final NotAuthorizedException item) {
            final List<Object> challenges = item.getChallenges();
            if (challenges == null || challenges.size() != 1) {
                return false;
            }
            final Object challenge = challenges.get(0);
            if (challenge == null) {
                return false;
            }
            final String challengeString = challenge.toString();
            return challengeString.startsWith("Bearer");
        }
    };

    protected ExampleSecretInjectionApplication<Session> configure() {
        SLF4JBridgeHandler.removeHandlersForRootLogger();
        SLF4JBridgeHandler.install();

        forceSet(CONTAINER_PORT, "0");

        return new ExampleSecretInjectionApplication<Session>();
    }

    /**
     * This demonstrates a client who provides the correct credentials, a valid
     * token, and passes all of the business rules to access the protected
     * resource.
     */
    @Test
    public final void verifySuccessfulBusinessRuleCheck() {
        // given
        final LoginRequest login = new LoginRequest("alice", "frog washer kirtle gaily fipple clunch");
        final Entity<LoginRequest> entity = Entity.json(login);
        final String tokenString =  target("session").request().accept(MediaType.TEXT_PLAIN_TYPE).post(entity, String.class);

        // when
        final String result = target("secrets").request().header("X-Authorization", tokenString).get(String.class);

        // then
        assertEquals("42", result);
    }

    /**
     * This demonstrates a client who provides the correct credentials, a valid
     * token, but does not pass the business rules required to access the
     * protected resource.
     */
    @Test
    public final void verifyFailedBusinessRuleCheck() {
        // given
        final LoginRequest login = new LoginRequest("mallory", "puling nach abend wield xenium holmos");
        final Entity<LoginRequest> entity = Entity.json(login);
        final String tokenString =  target("session").request().accept(MediaType.TEXT_PLAIN_TYPE).post(entity, String.class);

        // when / then
        assertThrows(ForbiddenException.class,
                () -> target("secrets")
                    .request()
                    .header("Authorization", "Bearer " + tokenString)
                    .get(String.class));
    }

    /**
     * This demonstrates a client who provides incorrect credentials and
     * therefore is not issued a token.
     */
    @Test
    public final void verifyFailedLogin() {
        // given
        final LoginRequest login = new LoginRequest("bob", "raia lehr import foehn read albata");
        final Entity<LoginRequest> entity = Entity.json(login);

        // when / then
        assertThrows(NotAuthorizedException.class,
                () -> target("session")
                    .request()
                    .accept(MediaType.TEXT_PLAIN_TYPE)
                    .post(entity, String.class));
    }

    /**
     * This demonstrates a client who attempts to forge a Fernet token but
     * cannot do so without knowing the secret key.
     */
    @Test
    public final void verifyFailedForgery() {
        // given
        final SecureRandom random = new SecureRandom();
        final Key invalidKey = Key.generateKey(random);
        final Token forgedToken = Token.generate(random, invalidKey, UUID.randomUUID().toString());
        final String tokenString = forgedToken.serialise();

        // when
        final NotAuthorizedException result =
                assertThrows(NotAuthorizedException.class,
                        () -> target("secrets")
                            .request()
                            .header("X-Authorization", tokenString)
                            .get(String.class));

        // then
        assertThat(result, notAuthorisedMatcher);
    }

    /**
     * This demonstrates a user logging out or otherwise having their
     * session revoked. Any Fernet tokens that are still valid according to
     * the Fernet spec can no longer be used.
     */
    @Test
    public final void verifyRevokedTokenUnusable() {
        // given
        final LoginRequest login = new LoginRequest("alice", "frog washer kirtle gaily fipple clunch");
        final Entity<LoginRequest> entity = Entity.json(login);
        final String tokenString = target("session").request().accept(MediaType.TEXT_PLAIN_TYPE).post(entity,
                String.class);

        try(Response revokeResponse = target("session").path("revocation").request(MediaType.TEXT_PLAIN_TYPE)
                .put(Entity.text(tokenString))) {
            assertEquals(204, revokeResponse.getStatus());

            // when / then
            assertThrows(ForbiddenException.class,
                    () -> target("secrets").request().header("X-Authorization", tokenString).get(String.class));
        }
    }

    /**
     * This demonstrates a user renewing their token and keeping their
     * session alive.
     */
    @Test
    public final void verifyRenewedTokenUsable() {
        // given
        final LoginRequest login = new LoginRequest("alice", "frog washer kirtle gaily fipple clunch");
        final String firstToken = target("session").request().accept(MediaType.TEXT_PLAIN_TYPE).post(Entity.json(login),
                String.class);
        final String secondToken = target("session").path("renewal").request(MediaType.TEXT_PLAIN_TYPE)
                .put(Entity.text(firstToken), String.class);
        // both tokens are usable, but the first one will expire sooner

        // when
        final String result = target("secrets").request().header("Authorization", "Bearer " + secondToken)
                .get(String.class);

        // then
        assertEquals("42", result);
    }

    @Test
    public final void verifyMissingTokenReturnsNotAuthorized() {
        // given

        // when
        final NotAuthorizedException result =
                assertThrows(NotAuthorizedException.class,
                        () -> target("secrets")
                            .request()
                            .get(String.class));

        // then
        assertThat(result, notAuthorisedMatcher);
    }

    @Test
    public final void verifyInvalidTokenReturnsNotAuthorized() {
        // given
        final SecureRandom random = new SecureRandom();
        final Key key = Key.generateKey(random);
        final byte[] plainText = "this is a valid token".getBytes(StandardCharsets.UTF_8);
        final Token validToken = Token.generate(random, key, plainText);
        final byte[] cipherText = key.encrypt(plainText, validToken.getInitializationVector());
        final Token invalidToken = new Token(validToken.getVersion(), validToken.getTimestamp(),
                validToken.getInitializationVector(), cipherText, key.sign(validToken.getVersion(),
                        validToken.getTimestamp(), validToken.getInitializationVector(), cipherText)) {

            public byte getVersion() {
                return (byte) (validToken.getVersion() + 1);
            }

            public Instant getTimestamp() {
                return validToken.getTimestamp().plus(Duration.ofDays(365));
            }

            public IvParameterSpec getInitializationVector() {
                final byte[] validVector = super.getInitializationVector().getIV();
                final byte[] invalidVector = new byte[validVector.length + 1];
                System.arraycopy(validVector, 0, invalidVector, 0, validVector.length);
                invalidVector[validVector.length] = 0;
                return new IvParameterSpec(invalidVector);
            }

        };

        // when
        final NotAuthorizedException result =
                assertThrows(NotAuthorizedException.class,
                        () -> target("secrets")
                            .request()
                            .header("Authorization", "Bearer " + invalidToken.serialise())
                            .get(String.class));

        // then
        assertThat(result, notAuthorisedMatcher);
    }

}