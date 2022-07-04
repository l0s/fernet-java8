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
package com.macasaet.fernet.jersey.example.tokeninjection;

import static org.glassfish.jersey.test.TestProperties.CONTAINER_PORT;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;

import java.security.SecureRandom;
import java.util.UUID;

import javax.ws.rs.ForbiddenException;
import javax.ws.rs.NotAuthorizedException;
import javax.ws.rs.client.Entity;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import org.glassfish.jersey.test.JerseyTest;
import org.junit.Test;
import org.slf4j.bridge.SLF4JBridgeHandler;

import com.macasaet.fernet.Key;
import com.macasaet.fernet.Token;
import com.macasaet.fernet.jersey.example.common.LoginRequest;

public class TokenInjectionIT extends JerseyTest {

    protected ExampleTokenInjectionApplication configure() {
        SLF4JBridgeHandler.removeHandlersForRootLogger();
        SLF4JBridgeHandler.install();
        forceSet(CONTAINER_PORT, "0");
        return new ExampleTokenInjectionApplication();
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
        final String result = target("secrets").request().header("Authorization", "Bearer " + tokenString).get(String.class);

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
                    .header("X-Authorization", tokenString)
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

        // when / then
        assertThrows(ForbiddenException.class,
                () -> target("secrets")
                    .request()
                    .header("Authorization", "Bearer\t" + tokenString)
                    .get(String.class));
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
                    () -> target("secrets").request().header("Authorization", "Bearer\t" + tokenString).get(String.class));
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
        final String result = target("secrets").request().header("X-Authorization", secondToken)
                .get(String.class);

        // then
        assertEquals("42", result);
    }

}