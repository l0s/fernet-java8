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

import java.util.List;
import java.util.stream.Collectors;

import javax.annotation.PreDestroy;
import javax.crypto.spec.IvParameterSpec;
import javax.inject.Inject;

import com.macasaet.fernet.Key;

import redis.clients.jedis.Jedis;
import redis.clients.jedis.JedisPool;

/**
 * An example utility for managing keys in a key rotation environment. 
 *
 * <p>Copyright &copy; 2017 Carlos Macasaet.</p>
 *
 * @author Carlos Macasaet
 */
public class RedisKeyRepository {

    private final JedisPool pool;

    /**
     * @param pool connection to Redis
     */
    @Inject
    public RedisKeyRepository(final JedisPool pool) {
        if (pool == null) {
            throw new IllegalArgumentException("pool cannot be null");
        }
        this.pool = pool;
    }

    /**
     * Communicate to the load balancer that this application can accept requests.
     *
     * @return true if and only if this repository has an active connection to the underlying datastore.
     */
    public boolean isHealthy() {
        return !getPool().isClosed();
    }

    @PreDestroy
    public void close() {
        pool.destroy();
    }

    /**
     * @return the current key for generating new tokens
     */
    public Key getPrimaryKey() {
        try (final Jedis jedis = getPool().getResource()) {
            final List<String> strings = jedis.lrange("fernet_keys", 1, 1);
            if( strings.isEmpty() ) {
                throw new IllegalStateException("no primary key found");
            }
            return new Key(strings.get(0));
        }
    }

    /**
     * @return all the keys that can be used to validate tokens and decrypt payloads
     */
    public List<Key> getDecryptionKeys() {
        try (final Jedis jedis = getPool().getResource()) {
            final List<String> strings = jedis.lrange("fernet_keys", 0, -1);
            return strings.parallelStream().map(DecryptionKey::new).collect(Collectors.toList());
        }
    }

    /**
     * @return the key in line to become primary. It should not be used for either generating or validating tokens.
     */
    public Key getStagedKey() {
        try (final Jedis jedis = getPool().getResource()) {
            final List<String> strings = jedis.lrange("fernet_keys", 0, 0);
            if( strings.isEmpty() ) {
                throw new IllegalStateException("no staged key found");
            }
            return new DecryptionKey(strings.get(0));
        }
    }

    protected JedisPool getPool() {
        return pool;
    }

    /**
     * A Fernet Key that only support decryption. In a system that employs key rotation, only the primary key should be
     * used to encrypt payloads and some number of decryption-only keys will be in use.
     *
     * <p>Copyright &copy; 2017 Carlos Macasaet.</p>
     *
     * @author Carlos Macasaet
     */
    protected static class DecryptionKey extends Key {
        public DecryptionKey(final String string) {
            super(string);
        }

        public byte[] encrypt(byte[] payload, IvParameterSpec initializationVector) {
            throw new UnsupportedOperationException();
        }
    }

}