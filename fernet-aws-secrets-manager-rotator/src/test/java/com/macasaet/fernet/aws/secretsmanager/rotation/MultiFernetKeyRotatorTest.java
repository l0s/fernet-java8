/**
   Copyright 2018 Carlos Macasaet

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
package com.macasaet.fernet.aws.secretsmanager.rotation;

import static com.macasaet.fernet.aws.secretsmanager.rotation.Stage.CURRENT;
import static com.macasaet.fernet.aws.secretsmanager.rotation.Stage.PENDING;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.MockitoAnnotations.initMocks;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Collection;

import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Spy;

import com.amazonaws.services.kms.AWSKMS;
import com.amazonaws.services.kms.model.GenerateRandomRequest;
import com.amazonaws.services.kms.model.GenerateRandomResult;
import com.macasaet.fernet.Key;

/**
 * <p>Copyright &copy; 2018 Carlos Macasaet.</p>
 * @author Carlos Macasaet
 */
public class MultiFernetKeyRotatorTest {

    @Mock
    private SecretsManager secretsManager;
    @Mock
    private AWSKMS kms;
    @Spy
    private SecureRandom random = new SecureRandom();
    @Captor
    private ArgumentCaptor<Collection<? extends Key>> keyCollector;

    @InjectMocks
    private MultiFernetKeyRotator rotator;

    @Rule
    public ExpectedException thrown = ExpectedException.none();

    @Before
    public void setUp() throws Exception {
        initMocks(this);
        rotator.setMaxActiveKeys(2);

        final GenerateRandomResult value = mock(GenerateRandomResult.class);
        given(value.getPlaintext()).willReturn(ByteBuffer.allocate(1024));
        given(kms.generateRandom(any(GenerateRandomRequest.class))).willReturn(value);
    }

    @After
    public void tearDown() throws Exception {
    }

    @Test
    public final void verifyCreateSecretAddsKeyAndRemovesOldest() throws IOException {
        // given
        final Key key0 = Key.generateKey(random);
        final Key key1 = Key.generateKey(random);
        final Key key2 = Key.generateKey(random);

        try( ByteArrayOutputStream stream = new ByteArrayOutputStream() ) {
            key0.writeTo(stream); // pending
            key1.writeTo(stream); // primary
            key2.writeTo(stream); // old key

            given(secretsManager.getSecretStage("secret", CURRENT)).willReturn(ByteBuffer.wrap(stream.toByteArray()));

            // when
            rotator.createSecret("secret", "version");

            // then
            verify(secretsManager).putSecretValue(eq("secret"), eq("version"), keyCollector.capture(), eq(PENDING));
            final Collection<? extends Key> keys = keyCollector.getValue();
            assertEquals(3, keys.size());
            assertTrue(keys.contains(key0)); // new pending key
            assertTrue(keys.contains(key1)); // primary key (old pending)
            assertFalse(keys.contains(key2)); // old key (old primary)
        }
    }

    @Test
    public final void verifyTestAcceptsValidSecret() throws IOException {
        // given
        final Key key0 = Key.generateKey(random);
        final Key key1 = Key.generateKey(random);
        final Key key2 = Key.generateKey(random);

        try (ByteArrayOutputStream stream = new ByteArrayOutputStream()) {
            key0.writeTo(stream);
            key1.writeTo(stream);
            key2.writeTo(stream);

            given(secretsManager.getSecretVersion("secret", "version")).willReturn(ByteBuffer.wrap(stream.toByteArray()));

            // when
            rotator.testSecret("secret", "version");

            // then (no exception)
        }
    }

    @Test
    public final void verifyTestRejectsTooFewBytes() throws IOException {
        // given
        final byte[] shortArray = new byte[ 6*32 - 1 ];
        Arrays.fill(shortArray, (byte)0);
        given( secretsManager.getSecretVersion("secret", "version")).willReturn(ByteBuffer.wrap(shortArray));

        // when
        thrown.expect(RuntimeException.class);
        rotator.testSecret("secret", "version");

        // then
    }

    @Test
    public final void verifyTestRejectsTooManyBytes() throws IOException {
        // given
        final byte[] shortArray = new byte[ 6*32 + 1 ];
        Arrays.fill(shortArray, (byte)0);
        given( secretsManager.getSecretVersion("secret", "version")).willReturn(ByteBuffer.wrap(shortArray));

        // when
        thrown.expect(RuntimeException.class);
        rotator.testSecret("secret", "version");

        // then
    }

    @Test
    public final void verifyCreateClearsIntermediateSecret() {
        // given
        final byte[] secretBytes = new byte[32];
        random.nextBytes(secretBytes);
        final int originalHashCode = Arrays.hashCode(secretBytes);
        final ByteBuffer secretByteBuffer = ByteBuffer.wrap(secretBytes);
        assertTrue(Arrays.equals(secretByteBuffer.array(), secretBytes));
        given(secretsManager.getSecretStage("secretId", CURRENT)).willReturn(secretByteBuffer);

        // when
        rotator.createSecret("secretId", "clientRequestToken");

        // then
        final byte[] modifiedBytes = secretByteBuffer.array();
        assertEquals(32, modifiedBytes.length);
        assertNotEquals(originalHashCode, Arrays.hashCode(secretBytes));
    }

    @Test
    public final void verifyTestClearsIntermediateSecret() {
        // given
        final byte[] secretBytes = new byte[32];
        for (byte i = 32; --i >= 0; secretBytes[i] = i);
        final int originalHashCode = Arrays.hashCode(secretBytes);
        final ByteBuffer secretByteBuffer = ByteBuffer.wrap(secretBytes);
        assertTrue(Arrays.equals(secretByteBuffer.array(), secretBytes));
        given(secretsManager.getSecretVersion("secretId", "clientRequestToken")).willReturn(secretByteBuffer);

        // when
        rotator.testSecret("secretId", "clientRequestToken");

        // then
        final byte[] modifiedBytes = secretByteBuffer.array();
        assertEquals(32, modifiedBytes.length);
        assertNotEquals(originalHashCode, Arrays.hashCode(secretBytes));
    }

}