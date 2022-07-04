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
package com.macasaet.fernet.jersey.example.common;

import java.security.SecureRandom;
import java.util.Collection;
import java.util.function.Supplier;

import javax.inject.Inject;
import javax.ws.rs.Consumes;
import javax.ws.rs.NotAuthorizedException;
import javax.ws.rs.POST;
import javax.ws.rs.PUT;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;

import com.macasaet.fernet.Key;
import com.macasaet.fernet.Token;
import com.macasaet.fernet.Validator;

/**
 * This is an example of a resource that generates a Fernet token. Here, the
 * Fernet token identifies a session. Once a client has started a session using
 * this resource, they can issue requests by providing only the token they have
 * been provided. They do not need to provide login credentials again until the
 * session expires or is revoked.
 *
 * <p>Copyright &copy; 2017 Carlos Macasaet.</p>
 *
 * @author Carlos Macasaet
 */
@Path("session")
public class AuthenticationResource {

	private final SecureRandom random = new SecureRandom();

	@Inject
	private PasswordService passwordService;
	@Inject
	private SessionRepository sessionRepository;
	@Inject
	private Validator<Session> sessionValidator;

    /**
     * This provides the secret keys. There is no need to share the keys
     * with the client. The resource that generates the tokens and the
     * resource that validates the tokens need not share the same
     * infrastructure as long as they both have access to the same keys.
     */
	@Inject
	private Supplier<Collection<Key>> keySupplier;

	/**
	 * This is an example of an endpoint that generates a new Fernet token. The
	 * client authenticates using this method then can use the token provided to
	 * perform secured operations. The client may, at their discretion, store
	 * the token insecurely (e.g. in a cookie or browser storage) since it will
	 * no longer be valid after the TTL (60 seconds by default).
	 *
	 * @param request
	 *            client credentials to create a new session token
	 * @return a Fernet token
	 */
	@POST
	@Produces(MediaType.TEXT_PLAIN)
	@Consumes(MediaType.APPLICATION_JSON)
	public String createSession(final LoginRequest request) {
		final User user = passwordService.authenticateUser(request.getUsername(), request.getPlainTextPassword());
		if (user != null) {
			// password is correct, so generate an ephemeral session
		    // store the session ID in the token payload
		    final Session session = new Session(request.getUsername());
		    sessionRepository.saveSession(session);

		    final Key key = keySupplier.get().iterator().next();
			final Token token = Token.generate(random, key, session.getId().toString());
			return token.serialise();
		}
		throw new NotAuthorizedException(Response.status(Status.UNAUTHORIZED).entity("invalid login").build());
	}

	@Path("/revocation")
	@PUT
	@Consumes(MediaType.TEXT_PLAIN)
    public void revokeSession(final String sessionToken) {
        final Token token = Token.fromString(sessionToken);

        // ensure this is a valid token and a non-revoked session
        final Session session = sessionValidator.validateAndDecrypt(keySupplier.get(), token);
        if (session != null) {
            // revoke the session for all associated Fernet tokens
            session.revoke();
            sessionRepository.revokeSession(session);
        }
    }

	@Path("/renewal")
	@PUT
	@Consumes(MediaType.TEXT_PLAIN)
	@Produces(MediaType.TEXT_PLAIN)
    public String renewSession(final String sessionToken) {
        final Token oldToken = Token.fromString(sessionToken);
        // ensure this is a valid token and a non-revoked session
        // if valid, extend the life of the session
        final Session session = sessionValidator.validateAndDecrypt(keySupplier.get(), oldToken);
        if (session != null) {
            // the session is valid, generate a new token
            // both the old and new tokens are valid, but the old one will expire
            // sooner as governed by the Fernet spec
            // revoking the session will revoke all associated Fernet tokens
            final Key key = keySupplier.get().iterator().next();
            final Token newToken = Token.generate(random, key, session.getId().toString());
            return newToken.serialise();
        }
        throw new NotAuthorizedException(Response.status(Status.UNAUTHORIZED).entity("invalid session token").build());
    }

}