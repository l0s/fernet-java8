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

import static java.util.Collections.unmodifiableMap;

import java.nio.CharBuffer;
import java.util.HashMap;
import java.util.Map;

import javax.inject.Singleton;

/**
 * Example of how to incorporate external storage into a Fernet token creation and validation scheme.
 *
 * <p>Copyright &copy; 2017 Carlos Macasaet.</p>
 *
 * @author Carlos Macasaet
 */
@Singleton
public class UserRepository {

    private final Map<String, User> datastore;

    {
        final Map<String, User> map = new HashMap<>();
        map.put("alice", new User(CharBuffer.wrap("$argon2id$v=19$m=4096$t=48$p=8$6X6h6b9CeF1hydBU5n0Mow$ZxI+2f0e5pjqL84uUdCuL4yXNmiiy/L4fIEcm+ewHo4"), true, "42"));
        map.put("bob", new User(CharBuffer.wrap("$argon2id$v=19$m=4096$t=48$p=8$YKQOlEgfpqS+30dEAY+Oiw$DVh47bymn+qHa069VIaQBbUpFFWz19kcjf9d8gbyjMY"), true, "524287"));
        map.put("mallory", new User(CharBuffer.wrap("$argon2id$v=19$m=4096$t=48$p=8$FVC8xnLcADH9NQ1HUrMhIQ$FuNHVh5XJmZWNW8f/NkPrtq9tySvJvEPjTI/kOOkzbo"), false, "665280"));
        datastore = unmodifiableMap(map);
    }

	public User findUser(final String username) {
		return datastore.get(username);
	}

    public User findUser(final Session session) {
        if (session == null) {
            return null;
        }
        final String username = session.getUsername();
        return findUser(username);
    }

}