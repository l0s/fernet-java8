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
package com.macasaet.fernet.example.rotation;

import java.util.Objects;

import javax.inject.Inject;

import com.macasaet.fernet.FernetKeyFactory;
import com.macasaet.fernet.Key;
import com.macasaet.fernet.Token;

import redis.clients.jedis.Jedis;
import redis.clients.jedis.JedisPool;
import redis.clients.jedis.Transaction;

/**
 * An example utility for rotating keys.
 *
 * <p>Copyright &copy; 2017 Carlos Macasaet.</p>
 *
 * @author Carlos Macasaet
 */
public class RedisKeyManager {

    private final FernetKeyFactory keyFactory;
    private final JedisPool pool;
    private final RedisKeyRepository repository;

    private int maxActiveKeys = 2;

    /**
     * @param keyFactory utility for generating new keys
     * @param pool connection to the underlying Redis datastore
     * @param repository utility for retrieving keys
     */
    @Inject
    public RedisKeyManager(final FernetKeyFactory keyFactory, final JedisPool pool, final RedisKeyRepository repository) {
        Objects.requireNonNull(keyFactory, "keyFactory cannot be null");
        Objects.requireNonNull(pool, "pool cannot be null");
        Objects.requireNonNull(repository, "repository cannot be null");
        this.keyFactory = keyFactory;
        this.pool = pool;
        this.repository = repository;
    }

    /**
     * This makes the staged key the new primary key, makes the primary key a validation-only key, deletes the oldest
     * validation-only key, and generates a new staged key. Note that this class is unaware of the TTL your application
     * uses to validate {@link Token Tokens}. So be mindful not to over-rotate your keys.
     */
    public void rotate() {
        final Key newStaged = getKeyFactory().generateKey();
        try (final Jedis jedis = getPool().getResource()) {
            try (final Transaction transaction = jedis.multi()) {
                transaction.lpush("fernet_keys", newStaged.serialise());
                transaction.ltrim("fernet_keys", 0, getMaxActiveKeys() - 1);
                transaction.exec();
            }
        }
    }

    /**
     * Generate a new set of keys for an empty repository.
     */
    public void initialiseNewRepository() {
        for (int i = getMaxActiveKeys(); --i >= 0; rotate());
    }

    protected FernetKeyFactory getKeyFactory() {
        return keyFactory;
    }

    protected JedisPool getPool() {
        return pool;
    }

    protected RedisKeyRepository getRepository() {
        return repository;
    }

    /**
     * @return the total number of keys in the system (including the primary and staged keys)
     */
    public int getMaxActiveKeys() {
        return maxActiveKeys;
    }

    /**
     * @param maxActiveKeys the total number of keys in the system (including the primary and staged keys)
     */
    public void setMaxActiveKeys(int maxActiveKeys) {
        if (maxActiveKeys < 2) {
            throw new IllegalArgumentException();
        }
        this.maxActiveKeys = maxActiveKeys;
    }

}