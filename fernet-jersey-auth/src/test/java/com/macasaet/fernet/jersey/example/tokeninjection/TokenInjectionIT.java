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

import static org.junit.Assert.assertEquals;

import java.security.SecureRandom;
import java.util.Random;

import javax.ws.rs.NotAuthorizedException;
import javax.ws.rs.client.Entity;
import javax.ws.rs.core.Application;
import javax.ws.rs.core.MediaType;

import org.glassfish.jersey.test.JerseyTest;
import org.glassfish.jersey.test.TestProperties;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import com.macasaet.fernet.Key;
import com.macasaet.fernet.Token;
import com.macasaet.fernet.jersey.example.common.LoginRequest;


public class TokenInjectionIT extends JerseyTest {

    @Rule
    public ExpectedException thrown = ExpectedException.none();

    protected Application configure() {
        enable(TestProperties.LOG_TRAFFIC);
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

        // when
        thrown.expect(NotAuthorizedException.class);
        target("secrets").request().header("X-Authorization", tokenString).get(String.class);

        // then (nothing)
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

        // when
        thrown.expect(NotAuthorizedException.class);
        target("session").request().accept(MediaType.TEXT_PLAIN_TYPE).post(entity, String.class);

        // then (nothing)
    }

    /**
     * This demonstrates a client who attempts to forge a Fernet token but
     * cannot do so without knowing the secret key.
     */
    @Test
    public final void verifyFailedForgery() {
        // given
        final Random random = new SecureRandom();
        final Key invalidKey = Key.generateKey(random);
        final Token forgedToken = Token.generate(random, invalidKey, "alice");
        final String tokenString = forgedToken.serialise();

        // when
        thrown.expect(NotAuthorizedException.class);
        target("secrets").request().header("X-Authorization", tokenString).get(String.class);

        // then (nothing)
    }

}