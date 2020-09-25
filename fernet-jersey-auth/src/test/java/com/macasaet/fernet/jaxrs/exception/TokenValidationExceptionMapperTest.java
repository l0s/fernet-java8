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
package com.macasaet.fernet.jaxrs.exception;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import javax.ws.rs.core.Response;

import org.junit.Before;
import org.junit.Test;

import com.macasaet.fernet.PayloadValidationException;
import com.macasaet.fernet.TokenExpiredException;
import com.macasaet.fernet.TokenValidationException;


public class TokenValidationExceptionMapperTest {

    private TokenValidationExceptionMapper mapper;

    @Before
    public void setUp() throws Exception {
        mapper = new TokenValidationExceptionMapper();
    }

    @Test
    public final void verifyToResponseGeneratesForbidden() {
        // given
        final PayloadValidationException exception = new PayloadValidationException("Invalid payload");

        // when
        final Response response = mapper.toResponse(exception);

        // then
        assertEquals(403, response.getStatus());
    }

    @Test
    public final void verifyToResponseGeneratesUnauthorized() {
        // given
        final TokenValidationException exception = new TokenExpiredException("token expired");

        // when
        final Response response = mapper.toResponse(exception);

        // then
        assertEquals(401, response.getStatus());
        final String challenge = response.getHeaderString("WWW-Authenticate");
        assertTrue(challenge.startsWith("Bearer "));
    }
}