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
 * This is an example of a POJO that may be used for both authentication and authorisation.
 *
 * <p>Copyright &copy; 2017 Carlos Macasaet.</p>
 *
 * @author Carlos Macasaet
 */
public class User {

    private CharSequence passwordHash;
    private boolean trustworthy;
    private String secret = "42";

    public User(final CharSequence passwordHash, final boolean trustworthy, final String secret) {
        setPasswordHash(passwordHash);
        setTrustworthy(trustworthy);
        setSecret(secret);
    }

    public CharSequence getPasswordHash() {
        return this.passwordHash;
    }

    protected void setPasswordHash(final CharSequence passwordHash) {
        if (passwordHash == null || passwordHash.length() == 0) {
            throw new IllegalArgumentException("passwordHash must be specified");
        }
        this.passwordHash = passwordHash;
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
     * @return a value that should only be presented to authenticated principals
     */
    public String getSecret() {
        return secret;
    }

    public void setSecret(String secret) {
        this.secret = secret;
    }

}