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
package com.macasaet.fernet.jersey.example.tokeninjection;

import java.util.Collection;
import java.util.function.Supplier;

import javax.inject.Inject;
import javax.ws.rs.ForbiddenException;
import javax.ws.rs.GET;
import javax.ws.rs.Path;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.macasaet.fernet.Key;
import com.macasaet.fernet.Token;
import com.macasaet.fernet.TokenValidationException;
import com.macasaet.fernet.Validator;
import com.macasaet.fernet.jaxrs.FernetToken;
import com.macasaet.fernet.jersey.example.common.Session;
import com.macasaet.fernet.jersey.example.common.User;
import com.macasaet.fernet.jersey.example.common.UserRepository;

/**
 * This is an example of a resource that is protected by Fernet tokens. In order
 * to access the resource, the client must pass a valid Fernet token that was
 * generated using the same secret key.
 *
 * <p>Copyright &copy; 2017 Carlos Macasaet.</p>
 *
 * @author Carlos Macasaet
 */
@Path("secrets")
public class ProtectedResource {

    /**
     * This provides the secret keys. There is no need to share it with the
     * client. The resource that generates the tokens and the resource that
     * validates the tokens need not share the same infrastructure as long
     * as they both have access to the same keys.
     */
    @Inject
    private Supplier<Collection<Key>> keySupplier;

	/**
	 * This is an example of a domain-specific token validator. It delegates to
	 * an external data store to convert the payload into an object. In
	 * addition, it applies domain-specific business rules to evaluate the
	 * deserialised payload.
	 */
    @Inject
    private Validator<Session> validator;

    @Inject
    private UserRepository userRepository;

    /**
     * This is a secured endpoint. The Fernet token is passed in via the X-Auth-Token header parameter.
     *
     * @param token
     *            a Fernet token
     * @return the secret information
     */
    @GET
    public String getSecret(@FernetToken final Token token) {
        // if a token was not provided or is not a well-formed Fernet token,
        // this
        // method will not execute
        try {
            // ensure that the token is valid and that the session is non-expired
            final Session session = validator.validateAndDecrypt(keySupplier.get(), token);
            final User user = userRepository.findUser(session);
            if (user != null && user.isTrustworthy()) {
                return user.getSecret();
            }
        } catch (final TokenValidationException tve) {
            // be sure the client cannot distinguish between invalid token, revoked
            // session, etc.
        }
        throw new ForbiddenException("access denied");
    }

}