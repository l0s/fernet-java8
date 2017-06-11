package com.macasaet.fernet.example.jaxrs;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Base64.Decoder;
import java.util.Base64.Encoder;
import java.util.Random;

public class User {

	private static final Random random = new SecureRandom();
	private static final Encoder encoder = Base64.getUrlEncoder();
	private static final Decoder decoder = Base64.getUrlDecoder();

	private String salt;
	private String twoRoundPasswordHash;
	private boolean trustworthy;

	public User() {
	}

	public User(final String singleRoundPasswordHash, final boolean trustworthy) {
		setPassword(singleRoundPasswordHash);
		setTrustworthy(trustworthy);
	}

	public String getSalt() {
		return salt;
	}

	protected void setSalt(String salt) {
		this.salt = salt;
	}

	public String getTwoRoundPasswordHash() {
		return twoRoundPasswordHash;
	}

	protected void setTwoRoundPasswordHash(final String passwordHash) {
		this.twoRoundPasswordHash = passwordHash;
	}

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

}