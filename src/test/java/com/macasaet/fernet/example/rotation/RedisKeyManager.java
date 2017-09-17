package com.macasaet.fernet.example.rotation;

import java.io.IOException;
import java.util.Random;

import javax.inject.Inject;

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

    private final Random random;
    private final JedisPool pool;
    private final RedisKeyRepository repository;

    private int maxActiveKeys = 2;

    /**
     * @param random entropy source used for generating new keys
     * @param pool connection to the underlying Redis datastore
     * @param repository utility for retrieving keys
     */
    @Inject
    public RedisKeyManager(final Random random, final JedisPool pool, final RedisKeyRepository repository) {
        if (random == null) {
            throw new IllegalArgumentException("random cannot be null");
        }
        if (pool == null) {
            throw new IllegalArgumentException("pool cannot be null");
        }
        if (repository == null) {
            throw new IllegalArgumentException("repository cannot be null");
        }
        this.random = random;
        this.pool = pool;
        this.repository = repository;
    }

    /**
     * This makes the staged key the new primary key, makes the primary key a validation-only key, deletes the oldest
     * validation-only key, and generates a new staged key. Note that this class is unaware of the TTL your application
     * uses to validate {@link Token Tokens}. So be mindful not to over-rotate your keys.
     */
    public void rotate() {
        final Key newStaged = Key.generateKey(getRandom());
        try (final Jedis jedis = getPool().getResource()) {
            try (final Transaction transaction = jedis.multi()) {
                transaction.lpush("fernet_keys", newStaged.serialise());
                transaction.ltrim("fernet_keys", 0, getMaxActiveKeys() - 1);
                transaction.exec();
            } catch (final IOException ioe) {
                throw new RuntimeException("Unable to rotate keys: " + ioe.getMessage(), ioe);
            }
        }
    }

    /**
     * Generate a new set of keys for an empty repository.
     */
    public void initialiseNewRepository() {
        for (int i = getMaxActiveKeys(); --i >= 0; rotate());
    }

    protected JedisPool getPool() {
        return pool;
    }

    protected RedisKeyRepository getRepository() {
        return repository;
    }

    protected Random getRandom() {
        return random;
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