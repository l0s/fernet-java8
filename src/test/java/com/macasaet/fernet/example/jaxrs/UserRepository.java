package com.macasaet.fernet.example.jaxrs;

import java.util.Map;

import javax.inject.Singleton;

import jersey.repackaged.com.google.common.collect.ImmutableMap;

/**
 * Example of how to incorporate external storage into a Fernet token creation and validation scheme.
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
