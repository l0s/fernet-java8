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

import javax.ws.rs.NotAuthorizedException;

import org.glassfish.jersey.server.ContainerRequest;

import com.macasaet.fernet.Token;

/**
 * This is a utility class for extracting Fernet tokens from HTTP headers.
 *
 * <p>Copyright &copy; 2018 Carlos Macasaet.</p>
 * @author Carlos Macasaet
 */
class TokenHeaderUtility {

    private static final String authenticationType = "Bearer";

    /**
     * Extract a Fernet token from an RFC6750 Authorization header.
     *
     * @param request a REST request which may or may not include an RFC6750 Authorization header.
     * @return a Fernet token or null if no RFC6750 Authorization header is provided.
     */
    @SuppressWarnings("PMD.AvoidLiteralsInIfCondition")
    public Token getAuthorizationToken(final ContainerRequest request) {
        String authorizationString = request.getHeaderString("Authorization");
        if (authorizationString != null && !"".equals(authorizationString)) {
            authorizationString = authorizationString.trim();
            final String[] components = authorizationString.split("\\s");
            if (components.length != 2) {
                throw new NotAuthorizedException(authenticationType);
            }
            final String scheme = components[0];
            if (!authenticationType.equalsIgnoreCase(scheme)) {
                throw new NotAuthorizedException(authenticationType);
            }
            final String tokenString = components[1];
            return Token.fromString(tokenString);
        }
        return null;
    }

    /**
     * Extract a Fernet token from an X-Authorization header.
     *
     * @param request a REST request which may or may not include an X-Authorization header.
     * @return a Fernet token or null if no X-Authorization header is provided.
     */
    public Token getXAuthorizationToken(final ContainerRequest request) {
        final String xAuthorizationString = request.getHeaderString("X-Authorization");
        if (xAuthorizationString != null && !"".equals(xAuthorizationString)) {
            return Token.fromString(xAuthorizationString.trim());
        }
        return null;
    }

}