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

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

import javax.inject.Singleton;

/**
 * A façade over the underlying {@link Session} data store. In this
 * example, a hash map is used, but for a distributed application, a
 * shared persistent data store would be used instead.
 *
 * <p>Copyright &copy; 2017-2021 Carlos Macasaet.</p>
 *
 * @author Carlos Macasaet
 */
@Singleton
public class SessionRepository {

    private final Clock clock = Clock.systemUTC();

    private final Map<UUID, Entry> sessions = new ConcurrentHashMap<>();

    /**
     * Find a session by its unique identifier and update its access time.
     *
     * @param id the unique session identifier
     * @return the active session or null if the session expired, was
     *         revoked, or never existed
     */
    public Session findSession(final UUID id) {
        final Entry entry = sessions.get(id);
        if (entry == null) {
            return null;
        }
        synchronized (entry) {
            if (entry.setAndCheckExpiration()) {
                sessions.remove(id);
                return null;
            }
            entry.access();
        }
        final Session session = entry.getSession();
        if (session.isRevoked()) {
            sessions.remove(id);
            return null;
        }
        return session;
    }

    /**
     * Persist a session for cross referencing with the payload of a Fernet
     * token.
     *
     * @param session an authenticated user session
     */
    public void saveSession(final Session session) {
        final Entry entry = sessions.computeIfAbsent(session.getId(), id -> new Entry(session));
        synchronized (entry) {
            entry.access();
        }
    }

    /**
     * Prevent a session from being reused. Call this if a user logs out or
     * if malicious behaviour from a session is detected and valid Fernet
     * tokens associated with that session should not be trusted.
     * 
     * @param session the session that should no longer be trusted
     */
    public void revokeSession(final Session session) {
        session.revoke();
        final Entry entry = sessions.get(session.getId());
        if (entry != null) {
            synchronized (entry) {
                // expire the entry for anyone else holding a reference to it
                entry.expireEarly();
            }
        }
        sessions.remove(session.getId());
    }

    protected class Entry {
        private final Session session;
        private boolean expired = false;
        private Instant lastAccess;

        public Entry(final Session session) {
            this.session = session;
            access();
        }

        public Session getSession() {
            return session;
        }

        public boolean setAndCheckExpiration() {
            expired |= lastAccess.plus(Duration.ofMinutes(30)).isBefore(clock.instant());
            return expired;
        }

        public void access() {
            lastAccess = clock.instant();
        }

        public void expireEarly() {
            expired |= true;
        }
    }

}