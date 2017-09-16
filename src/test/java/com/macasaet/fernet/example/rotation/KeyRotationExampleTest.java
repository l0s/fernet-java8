package com.macasaet.fernet.example.rotation;

import static org.junit.Assert.assertEquals;
import static org.mockito.MockitoAnnotations.initMocks;

import java.security.SecureRandom;
import java.util.Random;

import javax.servlet.http.HttpServletResponse;

import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.mockito.Mock;

import com.macasaet.fernet.TokenValidationException;

import redis.clients.jedis.Jedis;
import redis.clients.jedis.JedisPool;

/**
 * This class shows how one can incorporate a key-rotation mechanism when using Fernet tokens.
 *
 * This test is currently disabled because it requires an external Redis instance to be running.
 *
 * <p>Copyright &copy; 2017 Carlos Macasaet.</p>
 * @author Carlos Macasaet
 */
public class KeyRotationExampleTest {

    private JedisPool pool;
    private RedisKeyRepository repository;
    private RedisKeyManager manager;
    private ProtectedResource resource;

    @Mock
    private HttpServletResponse servletResponse;

    @Rule
    public ExpectedException thrown = ExpectedException.none();

//    @Before
    public void setUp() {
        initMocks(this);
        final Random random = new SecureRandom();
        pool = new JedisPool();
        repository = new RedisKeyRepository(pool);
        manager = new RedisKeyManager(random, pool, repository);
        manager.setMaxActiveKeys(3);

        clearData();
        manager.initialiseNewRepository();

        resource = new ProtectedResource(repository, random);
    }

//    @After
    public void tearDown() {
        clearData();
    }

    protected void clearData() {
        try (final Jedis jedis = pool.getResource()) {
            jedis.del("fernet_keys");
        }
    }

//    @Test
    public final void demonstrateKeyRotation() {
        final String initialToken = resource.issueToken("username", "password"); 

        manager.rotate();

        String result = resource.getSecret(initialToken);
        assertEquals("secret", result);

        manager.rotate();
        thrown.expect(TokenValidationException.class);
        resource.getSecret(initialToken);
    }

}