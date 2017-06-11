package com.macasaet.fernet.example.jaxrs;

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

	public void setUsername(String username) {
		this.username = username;
	}

	public String getSingleRoundPasswordHash() {
		return singleRoundPasswordHash;
	}

	public void setSingleRoundPasswordHash(String singleRoundPasswordHash) {
		this.singleRoundPasswordHash = singleRoundPasswordHash;
	}

}