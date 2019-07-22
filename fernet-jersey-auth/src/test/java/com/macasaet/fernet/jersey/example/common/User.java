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

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Base64.Decoder;
import java.util.Base64.Encoder;

/**
 * This is an example of a POJO that may be used for both authentication and authorisation.
 *
 * <p>Copyright &copy; 2017 Carlos Macasaet.</p>
 *
 * @author Carlos Macasaet
 */
public class User {

	private static final SecureRandom random = new SecureRandom();
	private static final Encoder encoder = Base64.getUrlEncoder();
	private static final Decoder decoder = Base64.getUrlDecoder();

	private String salt;
	private String twoRoundPasswordHash;
	private boolean trustworthy;
	private String secret = "42";

	public User() {
	}

	public User(final String singleRoundPasswordHash, final boolean trustworthy) {
		setPassword(singleRoundPasswordHash);
		setTrustworthy(trustworthy);
	}

	/**
	 * @return salt used to generate the two-round password hash
	 * @see #getTwoRoundPasswordHash()
	 */
	public String getSalt() {
		return salt;
	}

	protected void setSalt(String salt) {
		this.salt = salt;
	}

	/**
	 * @return the password as it is stored in the datastore. It is a function
	 *         of the single-round password hash and the salt
	 * @see #getSalt()
	 */
	public String getTwoRoundPasswordHash() {
		return twoRoundPasswordHash;
	}

	protected void setTwoRoundPasswordHash(final String passwordHash) {
		this.twoRoundPasswordHash = passwordHash;
	}

	/**
	 * A contrived field used for demonstrating domain-specific token validation.
	 */
	public boolean isTrustworthy() {
		return trustworthy;
	}

	public void setTrustworthy(boolean trustworthy) {
		this.trustworthy = trustworthy;
	}

	/**
	 * @param singleRoundPasswordHash password that has been hashed once between the client and the server (Base 64 URL encoded)
	 * @return true if and only if the password is correct
	 */
	public boolean isPasswordCorrect(final String singleRoundPasswordHash) {
		try {
			final MessageDigest digest = MessageDigest.getInstance("SHA-512");
			digest.update(decoder.decode(singleRoundPasswordHash));
			digest.update(decoder.decode(getSalt()));
			return MessageDigest.isEqual(digest.digest(), decoder.decode(getTwoRoundPasswordHash()));
		} catch (final NoSuchAlgorithmException e) {
			throw new RuntimeException("Password hashing algorithm not found: " + e.getMessage(), e);
		}
	}

	/**
	 * Set the salt and password based on a new single-round password hash.
	 *
	 * @param singleRoundPasswordHash SHA-256 hash of the plain-text password
	 */
	public void setPassword(final String singleRoundPasswordHash) {
		final byte[] bytes = new byte[16];
		random.nextBytes(bytes);
		setSalt(encoder.encodeToString(bytes));
		try {
			final MessageDigest digest = MessageDigest.getInstance("SHA-512");
			digest.update(decoder.decode(singleRoundPasswordHash));
			digest.update(decoder.decode(getSalt()));
			setTwoRoundPasswordHash(encoder.encodeToString(digest.digest()));
		} catch (final NoSuchAlgorithmException e) {
			throw new RuntimeException("Password hashing algorithm not found: " + e.getMessage(), e);
		}
    }

    /**
     * @return a value that should only be presented to authenticated principals
     */
    public String getSecret() {
        return secret;
    }

    public void setSecret(String secret) {
        this.secret = secret;
    }

}