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
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.MockitoAnnotations.openMocks;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Collection;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.Mock;

import com.amazonaws.services.kms.AWSKMS;
import com.amazonaws.services.kms.model.GenerateRandomRequest;
import com.amazonaws.services.kms.model.GenerateRandomResult;
import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.secretsmanager.model.DescribeSecretResult;
import com.amazonaws.services.secretsmanager.model.ResourceNotFoundException;
import com.amazonaws.util.StringInputStream;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.collect.ImmutableMap;
import com.macasaet.fernet.Key;

/**
 * <p>Copyright &copy; 2018 Carlos Macasaet.</p>
 * @author Carlos Macasaet
 */
public class MultiFernetKeyRotatorTest {

    private AutoCloseable mockContext;
    @Mock
    private SecretsManager secretsManager;
    @Mock
    private AWSKMS kms;
    private SecureRandom random = new SecureRandom();
    @Captor
    private ArgumentCaptor<Collection<? extends Key>> keyCollector;

    private MultiFernetKeyRotator rotator;

    @Before
    public void setUp() throws Exception {
        mockContext = openMocks(this);
        rotator = new MultiFernetKeyRotator(secretsManager, kms, random);
        rotator.setMaxActiveKeys(2);

        final GenerateRandomResult value = mock(GenerateRandomResult.class);
        given(value.getPlaintext()).willReturn(ByteBuffer.allocate(1024));
        given(kms.generateRandom(any(GenerateRandomRequest.class))).willReturn(value);
    }

    @After
    public void tearDown() throws Exception {
        mockContext.close();
    }

    @Test
    public final void verifyCreateSecretAddsKeyAndRemovesOldest() throws IOException {
        // given
        final Key key0 = Key.generateKey(random);
        final Key key1 = Key.generateKey(random);
        final Key key2 = Key.generateKey(random);
        final DescribeSecretResult description = new DescribeSecretResult();
        description.setRotationEnabled(true);
        description.setVersionIdsToStages(ImmutableMap.of("version", Arrays.asList("AWSPENDING")));

        final InputStream input = new StringInputStream(
                "{\"Step\": \"createSecret\",\"ClientRequestToken\": \"version\",\"SecretId\":\"secret\"}");
        final ByteArrayOutputStream output = new ByteArrayOutputStream();
        final Context context = mock(Context.class);

        try (ByteArrayOutputStream stream = new ByteArrayOutputStream()) {
            key0.writeTo(stream); // pending
            key1.writeTo(stream); // primary
            key2.writeTo(stream); // old key

            given(secretsManager.getSecretStage("secret", CURRENT)).willReturn(ByteBuffer.wrap(stream.toByteArray()));
            given(secretsManager.describeSecret("secret")).willReturn(description);
            given(secretsManager.getSecretVersion("secret", "version")).willThrow(new ResourceNotFoundException(""));

            // when
            rotator.handleRequest(input, output, context);

            // then
            verify(secretsManager).putSecretValue(eq("secret"), eq("version"), keyCollector.capture(), eq(PENDING));
            final Collection<? extends Key> keys = keyCollector.getValue();
            assertEquals(3, keys.size());
            assertTrue(keys.contains(key0)); // new pending key
            assertTrue(keys.contains(key1)); // primary key (old pending)
            assertFalse(keys.contains(key2)); // old key (old primary)
            new ObjectMapper().readTree(output.toByteArray());
        }
    }

    @Test
    public final void verifyTestAcceptsValidSecret() throws IOException {
        // given
        final Key key0 = Key.generateKey(random);
        final Key key1 = Key.generateKey(random);
        final Key key2 = Key.generateKey(random);
        final DescribeSecretResult description = new DescribeSecretResult();
        description.setRotationEnabled(true);
        description.setVersionIdsToStages(ImmutableMap.of("version", Arrays.asList("AWSPENDING")));
        final InputStream input = new StringInputStream(
                "{\"Step\": \"testSecret\",\"ClientRequestToken\": \"version\",\"SecretId\":\"secret\"}");
        final ByteArrayOutputStream output = new ByteArrayOutputStream();
        final Context context = mock(Context.class);

        try (ByteArrayOutputStream stream = new ByteArrayOutputStream()) {
            key0.writeTo(stream);
            key1.writeTo(stream);
            key2.writeTo(stream);

            given(secretsManager.getSecretVersion("secret", "version")).willReturn(ByteBuffer.wrap(stream.toByteArray()));
            given(secretsManager.getSecretStage("secret", CURRENT)).willReturn(ByteBuffer.wrap(stream.toByteArray()));
            given(secretsManager.describeSecret("secret")).willReturn(description);

            // when
            rotator.handleRequest(input, output, context);

            // then
            new ObjectMapper().readTree(output.toByteArray());
        }
    }

    @Test
    public final void verifyTestRejectsTooFewBytes() throws IOException {
        // given
        final byte[] shortArray = new byte[6 * 32 - 1];
        Arrays.fill(shortArray, (byte) 0);
        final DescribeSecretResult description = new DescribeSecretResult();
        description.setRotationEnabled(true);
        description.setVersionIdsToStages(ImmutableMap.of("version", Arrays.asList("AWSPENDING")));
        final InputStream input = new StringInputStream(
                "{\"Step\": \"testSecret\",\"ClientRequestToken\": \"version\",\"SecretId\":\"secret\"}");
        final ByteArrayOutputStream output = new ByteArrayOutputStream();
        final Context context = mock(Context.class);
        given(secretsManager.getSecretVersion("secret", "version")).willReturn(ByteBuffer.wrap(shortArray));
        given(secretsManager.describeSecret("secret")).willReturn(description);

        // when / then
        assertThrows(IllegalStateException.class, () -> rotator.handleRequest(input, output, context));
        new ObjectMapper().readTree(output.toByteArray());
    }

    @Test
    public final void verifyTestRejectsTooManyBytes() throws IOException {
        // given
        final byte[] longArray = new byte[6 * 32 + 1];
        Arrays.fill(longArray, (byte) 0);
        final DescribeSecretResult description = new DescribeSecretResult();
        description.setRotationEnabled(true);
        description.setVersionIdsToStages(ImmutableMap.of("version", Arrays.asList("AWSPENDING")));
        final InputStream input = new StringInputStream(
                "{\"Step\": \"testSecret\",\"ClientRequestToken\": \"version\",\"SecretId\":\"secret\"}");
        final ByteArrayOutputStream output = new ByteArrayOutputStream();
        final Context context = mock(Context.class);
        given(secretsManager.getSecretVersion("secret", "version")).willReturn(ByteBuffer.wrap(longArray));
        given(secretsManager.describeSecret("secret")).willReturn(description);

        // when / then
        assertThrows(RuntimeException.class, () -> rotator.handleRequest(input, output, context));
        new ObjectMapper().readTree(output.toByteArray());
    }

    @Test
    public final void verifyCreateClearsIntermediateSecret() throws IOException {
        // given
        final byte[] secretBytes = new byte[32];
        random.nextBytes(secretBytes);
        final int originalHashCode = Arrays.hashCode(secretBytes);
        final ByteBuffer secretByteBuffer = ByteBuffer.wrap(secretBytes);
        assertTrue(Arrays.equals(secretByteBuffer.array(), secretBytes));
        final DescribeSecretResult description = new DescribeSecretResult();
        description.setRotationEnabled(true);
        description.setVersionIdsToStages(ImmutableMap.of("clientRequestToken", Arrays.asList("AWSPENDING")));
        given(secretsManager.getSecretStage("secretId", CURRENT)).willReturn(secretByteBuffer);
        given(secretsManager.describeSecret("secretId")).willReturn(description);
        given(secretsManager.getSecretVersion("secretId", "clientRequestToken"))
                .willThrow(new ResourceNotFoundException(""));

        final InputStream input = new StringInputStream(
                "{\"Step\": \"createSecret\",\"ClientRequestToken\": \"clientRequestToken\",\"SecretId\":\"secretId\"}");
        final ByteArrayOutputStream output = new ByteArrayOutputStream();
        final Context context = mock(Context.class);

        // when
        rotator.handleRequest(input, output, context);

        // then
        final byte[] modifiedBytes = secretByteBuffer.array();
        assertEquals(32, modifiedBytes.length);
        assertNotEquals(originalHashCode, Arrays.hashCode(secretBytes));
        new ObjectMapper().readTree(output.toByteArray());
    }

    @Test
    public final void verifyTestClearsIntermediateSecret() throws IOException {
        // given
        final byte[] secretBytes = new byte[32];
        for (byte i = 32; --i >= 0; secretBytes[i] = i);
        final int originalHashCode = Arrays.hashCode(secretBytes);
        final ByteBuffer secretByteBuffer = ByteBuffer.wrap(secretBytes);
        assertTrue(Arrays.equals(secretByteBuffer.array(), secretBytes));
        final DescribeSecretResult description = new DescribeSecretResult();
        description.setRotationEnabled(true);
        description.setVersionIdsToStages(ImmutableMap.of("clientRequestToken", Arrays.asList("AWSPENDING")));
        final InputStream input = new StringInputStream(
                "{\"Step\": \"testSecret\",\"ClientRequestToken\": \"clientRequestToken\",\"SecretId\":\"secretId\"}");
        final ByteArrayOutputStream output = new ByteArrayOutputStream();
        final Context context = mock(Context.class);
        given(secretsManager.getSecretVersion("secretId", "clientRequestToken")).willReturn(secretByteBuffer);
        given(secretsManager.describeSecret("secretId")).willReturn(description);

        // when
        rotator.handleRequest(input, output, context);

        // then
        final byte[] modifiedBytes = secretByteBuffer.array();
        assertEquals(32, modifiedBytes.length);
        assertNotEquals(originalHashCode, Arrays.hashCode(secretBytes));
        new ObjectMapper().readTree(output.toByteArray());
    }

}