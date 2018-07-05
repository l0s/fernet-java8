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

	public LoginRequest() {
	}

	public LoginRequest(String username, String singleRoundPasswordHash) {
	    this();
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