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
package com.macasaet.fernet.jersey;

import static javax.ws.rs.core.Response.status;
import static javax.ws.rs.core.Response.Status.UNAUTHORIZED;

import javax.ws.rs.WebApplicationException;

import org.glassfish.jersey.server.ContainerRequest;

import com.macasaet.fernet.Token;

class TokenHeaderUtility {

    public Token getAuthorizationToken(final ContainerRequest request) {
        String authorizationString = request.getHeaderString("Authorization");
        if (authorizationString != null && !"".equals(authorizationString)) {
            authorizationString = authorizationString.trim();
            final String[] components = authorizationString.split(" "); // TODO match all whitespace
            if (components.length != 2) {
                throw new WebApplicationException(status(UNAUTHORIZED).entity("mal-formed RFC2617 header").build());
            }
            final String scheme = components[0];
            if (!"Fernet".equalsIgnoreCase(scheme)) {
                throw new WebApplicationException(
                        status(UNAUTHORIZED).entity("unrecognised RFC2617 authorization scheme").build());
            }
            final String tokenString = components[1];
            return Token.fromString(tokenString);
        }
        return null;
    }

    public Token getXAuthorizationToken(final ContainerRequest request) {
        final String xAuthorizationString = request.getHeaderString("X-Authorization");
        if (xAuthorizationString != null && !"".equals(xAuthorizationString)) {
            return Token.fromString(xAuthorizationString.trim());
        }
        return null;
    }

}