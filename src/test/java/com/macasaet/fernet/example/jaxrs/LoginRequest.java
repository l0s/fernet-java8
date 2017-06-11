package com.macasaet.fernet.example.jaxrs;

/**
 * User credentials for requesting a session token. In order to prevent
 * intermediary nodes from learning the password, a SHA-256 hash of the password
 * should be passed instead of the plain text password.
 *
 * <p>Copyright &copy; 2017 Carlos Macasaet.</p>
 *
 * @author Carlos Macasaet
 */
public class LoginRequest {

	private String username;
	private String singleRoundPasswordHash;

	public LoginRequest(String username, String singleRoundPasswordHash) {
		setUsername(username);
		setSingleRoundPasswordHash(singleRoundPasswordHash);
	}

	public String getUsername() {
		return username;
	}

	protected void setUsername(String username) {
		this.username = username;
	}

	/**
	 * @return the SHA-256 hash of the plain-text password
	 */
	public String getSingleRoundPasswordHash() {
		return singleRoundPasswordHash;
	}

	protected void setSingleRoundPasswordHash(String singleRoundPasswordHash) {
		this.singleRoundPasswordHash = singleRoundPasswordHash;
	}

}