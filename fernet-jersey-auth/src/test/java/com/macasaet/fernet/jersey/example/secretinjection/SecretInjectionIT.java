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

import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;

import java.io.UnsupportedEncodingException;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.List;

import javax.crypto.spec.IvParameterSpec;
import javax.ws.rs.ForbiddenException;
import javax.ws.rs.NotAuthorizedException;
import javax.ws.rs.client.Entity;
import javax.ws.rs.core.Application;
import javax.ws.rs.core.MediaType;

import org.glassfish.jersey.test.JerseyTest;
import org.hamcrest.CustomTypeSafeMatcher;
import org.hamcrest.Matcher;
import org.junit.Test;
import org.slf4j.bridge.SLF4JBridgeHandler;

import com.macasaet.fernet.Key;
import com.macasaet.fernet.Token;
import com.macasaet.fernet.jersey.example.common.LoginRequest;
import com.macasaet.fernet.jersey.example.common.User;

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

    protected Application configure() {
        SLF4JBridgeHandler.removeHandlersForRootLogger();
        SLF4JBridgeHandler.install();

        return new ExampleSecretInjectionApplication<User>();
    }

    /**
     * This demonstrates a client who provides the correct credentials, a valid
     * token, and passes all of the business rules to access the protected
     * resource.
     */
    @Test
    public final void verifySuccessfulBusinessRuleCheck() {
        // given
        final LoginRequest login = new LoginRequest("alice", "1QYCGznPQ1z8T1aX_CNXKheDMAnNSfq_xnSxWXPLeKU=");
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
        final LoginRequest login = new LoginRequest("mallory", "Lpei3NWxhPsyc5NrJp6zkbHj4P_bji6Z7GsY0JSAUb8=");
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
        final LoginRequest login = new LoginRequest("bob", "NReIudfT_iovLMo-MCX8sClVr3UwbeEhAq7er6X_Kps=");
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
        final Token forgedToken = Token.generate(random, invalidKey, "alice");
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
    public final void verifyInvalidTokenReturnsNotAuthorized() throws UnsupportedEncodingException {
        // given
        final SecureRandom random = new SecureRandom();
        final Key key = Key.generateKey(random);
        final byte[] plainText = "this is a valid token".getBytes("UTF-8");
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