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

import java.util.Map;

import javax.inject.Singleton;

import jersey.repackaged.com.google.common.collect.ImmutableMap;

/**
 * Example of how to incorporate external storage into a Fernet token creation and validation scheme.
 *
 * <p>Copyright &copy; 2017 Carlos Macasaet.</p>
 *
 * @author Carlos Macasaet
 */
@Singleton
public class UserRepository {

	private Map<String, User> datastore =
			ImmutableMap.of("alice", new User("1QYCGznPQ1z8T1aX_CNXKheDMAnNSfq_xnSxWXPLeKU=", true),
					"bob", new User("98UXS8DlhmSuc6-PtTnFNV7cJGluRn1z4By-W_IMs4Q=", true),
					"mallory", new User("Lpei3NWxhPsyc5NrJp6zkbHj4P_bji6Z7GsY0JSAUb8=", false));

	public User findUser(final String username) {
		return datastore.get(username);
	}

}
