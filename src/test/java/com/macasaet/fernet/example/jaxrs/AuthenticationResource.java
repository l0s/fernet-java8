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
package com.macasaet.fernet.example.jaxrs;

import java.security.SecureRandom;
import java.util.Random;

import javax.inject.Inject;
import javax.ws.rs.NotAuthorizedException;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;

import com.macasaet.fernet.Key;
import com.macasaet.fernet.Token;

/**
 * This is an example of a resource that generates a Fernet token. Here, the
 * Fernet token identifies a session. Once a client has started a session using
 * this resource, they can issue requests by providing only the token they have
 * been provided. The do not need to provide login credentials again until the
 * token expires.
 *
 * <p>Copyright &copy; 2017 Carlos Macasaet.</p>
 *
 * @author Carlos Macasaet
 */
@Path("session")
public class AuthenticationResource {

	@Inject
	Random random = new SecureRandom();

	/**
	 * This is the secret key. There is no need to share it with the client. The
	 * resource that generates the tokens and the resource that validates the
	 * tokens need not share the same infrastructure as long as they both have
	 * access to the same key.
	 */
	final Key key = new Key("oTWTxEsH8OZ2jNR64dibSaBHyj_CX2RGP-eBRxjlkoc=");

	@Inject
	UserRepository repository;

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
	@Produces("text/plain")
	public String createSession(final LoginRequest request) {
		final User user = repository.findUser(request.getUsername());
		if (user.isPasswordCorrect(request.getSingleRoundPasswordHash())) {
			// password is correct, so generate a Fernet token
			// payload is the username, but it could easily be JSON or XML
			final Token token = Token.generate(random, key, request.getUsername());
			return token.serialise();
		}
		throw new NotAuthorizedException(Response.status(Status.UNAUTHORIZED).entity("bad password").build());
	}

}