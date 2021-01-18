/**
   Copyright 2017-2021 Carlos Macasaet

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       https://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
 */
package com.macasaet.fernet.jersey.example.common;

import java.util.UUID;

/**
 * An ephemeral session. A user will have a single session for each
 * device through which they are logged in. A session will be associated
 * with one or more Fernet tokens. Revoking a session will invalidate
 * all the associated tokens.
 * 
 * <p>Copyright &copy; 2017-2021 Carlos Macasaet.</p>
 *
 * @author Carlos Macasaet
 */
public class Session {

    private final UUID id = UUID.randomUUID();
    private final String username;
    private boolean revoked = false;

    public Session(String username) {
        this.username = username;
    }

    public UUID getId() {
        return id;
    }

    public String getUsername() {
        return username;
    }

    /**
     * Check if a session is revoked. If a session object does not exist or
     * this method returns false, consider the session invalid, even if a
     * valid Fernet token was provided.
     * 
     * @return true if and only if the session has been revoked.
     */
    public boolean isRevoked() {
        return revoked;
    }

    /**
     * Prevent this session from being reused. Call this if a user logs out
     * or if malicious behaviour from a session is detected and valid Fernet
     * tokens associated with that session should not be trusted.
     */
    public void revoke() {
        revoked |= true;
    }

}