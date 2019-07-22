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
package com.macasaet.fernet.example.rotation;

import java.security.SecureRandom;

import javax.inject.Inject;
import javax.ws.rs.GET;
import javax.ws.rs.HeaderParam;
import javax.ws.rs.NotAuthorizedException;
import javax.ws.rs.POST;
import javax.ws.rs.Path;

import com.macasaet.fernet.Key;
import com.macasaet.fernet.StringValidator;
import com.macasaet.fernet.Token;
import com.macasaet.fernet.TokenValidationException;
import com.macasaet.fernet.Validator;

/**
 * An example of a resource protected by Fernet tokens in an environment in which keys are rotated.
 *
 * <p>Copyright &copy; 2017 Carlos Macasaet.</p>
 * @author Carlos Macasaet
 */
@Path("resource")
public class ProtectedResource {

    private final RedisKeyRepository keyRepository;
    private final SecureRandom random;

    private final Validator<String> validator = new StringValidator() {
    };

    /**
     * @param keyRepository a utility for managing rotated keys
     * @param random a source of entropy for generating new tokens
     */
    @Inject
    public ProtectedResource(final RedisKeyRepository keyRepository, final SecureRandom random) {
        if (keyRepository == null) {
            throw new IllegalArgumentException("keyRepository cannot be null");
        }
        if (random == null) {
            throw new IllegalArgumentException("random cannot be null");
        }
        this.keyRepository = keyRepository;
        this.random = random;
    }

    /**
     * @param authToken a valid Fernet token
     * @return the secured value
     * @throws TokenValidationException if an invalid token was provided
     */
    @GET
    @Path("secret")
    public String getSecret(@HeaderParam("X-Auth-Token") final String authToken) {
        final Token token = Token.fromString(authToken);
        token.validateAndDecrypt(getKeyRepository().getDecryptionKeys(), getValidator());
        return "secret";
    }

    /**
     * @param username a valid username
     * @param password the password for the user <em>username</em>
     * @return a new Fernet token if and only if the credentials are valid
     * @throws NotAuthorizedException if invalid credentials are provided
     */
    @POST
    @Path("token")
    public String issueToken(final String username, final String password) {
        if ("username".equals(username) && "password".equals(password)) {
            // might be nice to have Token.generate(repository, payload)
            final Key primaryKey = getKeyRepository().getPrimaryKey();
            final Token token = Token.generate(random, primaryKey, username);
            return token.serialise();
        }
        throw new NotAuthorizedException("Bearer realm=\"secrets\"");
    }

    protected RedisKeyRepository getKeyRepository() {
        return keyRepository;
    }

    protected Validator<String> getValidator() {
        return validator;
    }

}