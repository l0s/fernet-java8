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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;
import static org.mockito.MockitoAnnotations.openMocks;

import java.io.IOException;
import java.security.SecureRandom;

import javax.servlet.http.HttpServletResponse;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mock;

import com.macasaet.fernet.TokenValidationException;

import redis.clients.jedis.Jedis;
import redis.clients.jedis.JedisPool;
import redis.embedded.RedisServer;

/**
 * This class shows how one can incorporate a key-rotation mechanism when using Fernet tokens.
 *
 * This test is currently disabled because it requires an external Redis instance to be running.
 *
 * <p>Copyright &copy; 2017 Carlos Macasaet.</p>
 * @author Carlos Macasaet
 */
public class KeyRotationExampleIT {

    private AutoCloseable mockContext;
    private RedisServer redisServer;
    private JedisPool pool;
    private RedisKeyRepository repository;
    private RedisKeyManager manager;
    private ProtectedResource resource;

    @Mock
    private HttpServletResponse servletResponse;

    @Before
    public void setUp() throws IOException {
        mockContext = openMocks(this);
        final SecureRandom random = new SecureRandom();
        redisServer = new RedisServer();
        redisServer.start();

        pool = new JedisPool();
        repository = new RedisKeyRepository(pool);
        manager = new RedisKeyManager(random, pool, repository);
        manager.setMaxActiveKeys(3);

        clearData();
        manager.initialiseNewRepository();

        resource = new ProtectedResource(repository, random);
    }

    @After
    public void tearDown() throws Exception {
        try {
            try {
                clearData();
            } finally {
                redisServer.stop();
            }
        } finally {
            mockContext.close();
        }
    }

    protected void clearData() {
        try (final Jedis jedis = pool.getResource()) {
            jedis.del("fernet_keys");
        }
    }

    @Test
    public final void demonstrateKeyRotation() {
        final String initialToken = resource.issueToken("username", "password"); 

        manager.rotate();

        String result = resource.getSecret(initialToken);
        assertEquals("secret", result);

        manager.rotate();
        assertThrows(TokenValidationException.class, () -> resource.getSecret(initialToken));
    }

}