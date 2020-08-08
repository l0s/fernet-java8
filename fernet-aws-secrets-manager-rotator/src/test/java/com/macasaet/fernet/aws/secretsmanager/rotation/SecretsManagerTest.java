/**
   Copyright 2018 Carlos Macasaet

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
package com.macasaet.fernet.aws.secretsmanager.rotation;

import static com.macasaet.fernet.aws.secretsmanager.rotation.Stage.PENDING;
import static com.macasaet.fernet.aws.secretsmanager.rotation.Stage.PREVIOUS;
import static java.util.Arrays.asList;
import static java.util.Collections.singleton;
import static java.util.Collections.singletonList;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.MockitoAnnotations.openMocks;

import java.io.IOException;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.nio.ByteBuffer;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;

import com.amazonaws.services.secretsmanager.AWSSecretsManager;
import com.amazonaws.services.secretsmanager.model.DescribeSecretRequest;
import com.amazonaws.services.secretsmanager.model.DescribeSecretResult;
import com.amazonaws.services.secretsmanager.model.GetSecretValueRequest;
import com.amazonaws.services.secretsmanager.model.GetSecretValueResult;
import com.amazonaws.services.secretsmanager.model.PutSecretValueRequest;
import com.amazonaws.services.secretsmanager.model.ResourceNotFoundException;
import com.amazonaws.services.secretsmanager.model.UpdateSecretVersionStageRequest;
import com.macasaet.fernet.Key;

/**
 * <p>Copyright &copy; 2018 Carlos Macasaet.</p>
 * @author Carlos Macasaet
 */
public class SecretsManagerTest {

    private AutoCloseable mockContext;
    @Mock
    private AWSSecretsManager delegate;
    @InjectMocks
    private SecretsManager manager;

    @Before
    public void setUp() {
        mockContext = openMocks(this);
    }

    @After
    public void tearDown() throws Exception {
        mockContext.close();
    }

    @Test
    public final void verifyAssertCurrentStageExistsThrowsException() {
        // given
        final GetSecretValueRequest request = new GetSecretValueRequest();
        request.setSecretId("secret");
        request.setVersionStage("AWSCURRENT");
        given(delegate.getSecretValue(eq(request))).willThrow(new ResourceNotFoundException("not found"));

        // when / then (exception thrown)
        assertThrows(ResourceNotFoundException.class, () -> manager.assertCurrentStageExists("secret"));
    }

    @Test
    public final void verifyAssertDoesNothing() {
        // given
        final GetSecretValueRequest request = new GetSecretValueRequest();
        request.setSecretId("secret");
        request.setVersionStage("AWSCURRENT");
        given(delegate.getSecretValue(eq(request))).willReturn(new GetSecretValueResult());

        // when
        manager.assertCurrentStageExists("secret");

        // then (nothing)
    }

    @Test
    public final void verifyDescribeSecretPassesThrough() {
        // given
        final DescribeSecretRequest request = new DescribeSecretRequest();
        request.setSecretId("secret");
        final DescribeSecretResult sampleResult = new DescribeSecretResult();
        sampleResult.setRotationEnabled(true);
        sampleResult.addVersionIdsToStagesEntry("version", singletonList("AWSPREVIOUS"));
        given(delegate.describeSecret(eq(request))).willReturn(sampleResult);

        // when
        final DescribeSecretResult result = manager.describeSecret("secret");

        // then
        assertTrue(result.isRotationEnabled());
        assertTrue(result.getVersionIdsToStages().get("version").contains("AWSPREVIOUS"));
    }

    @Test
    public final void verifyGetSecretVersionRetrievesBinary() throws UnsupportedEncodingException {
        // given
        final GetSecretValueRequest request = new GetSecretValueRequest();
        request.setSecretId("secret");
        request.setVersionId("version");
        final GetSecretValueResult response = new GetSecretValueResult();
        response.setSecretBinary(ByteBuffer.wrap("expected".getBytes("UTF-8")));
        given(delegate.getSecretValue(eq(request))).willReturn(response);

        // when
        final ByteBuffer result = manager.getSecretVersion("secret", "version");

        // then
        final byte[] buffer = new byte[result.remaining()];
        result.get(buffer);
        assertEquals("expected", new String(buffer, "UTF-8"));
    }

    @Test
    public final void verifyGetSecretStageRetrievesBinary() throws UnsupportedEncodingException {
        // given
        final GetSecretValueRequest request = new GetSecretValueRequest();
        request.setSecretId("secret");
        request.setVersionStage("AWSPENDING");
        final GetSecretValueResult response = new GetSecretValueResult();
        response.setSecretBinary(ByteBuffer.wrap("expected".getBytes("UTF-8")));
        given(delegate.getSecretValue(eq(request))).willReturn(response);

        // when
        final ByteBuffer result = manager.getSecretStage("secret", PENDING);

        // then
        final byte[] buffer = new byte[result.remaining()];
        result.get(buffer);
        assertEquals("expected", new String(buffer, "UTF-8"));
    }

    @Test
    public final void verifyRotateSecretTagsNewKeyAndUntagsOldKey() {
        // given
        // when
        manager.rotateSecret("secret", "new", "old");

        // then
        final UpdateSecretVersionStageRequest request = new UpdateSecretVersionStageRequest();
        request.setSecretId("secret");
        request.setVersionStage("AWSCURRENT");
        request.setMoveToVersionId("new");
        request.setRemoveFromVersionId("old");
        verify(delegate).updateSecretVersionStage(eq(request));
    }

    @Test
    public final void verifyPutSecretValueStoresKey() throws IOException {
        // given
        final String expected = "expected";
        final Key key = mock(Key.class);
        final Answer<?> answer = new Answer<Void>() {
            public Void answer(final InvocationOnMock invocation) throws Throwable {
                final OutputStream stream = invocation.getArgument(0);
                stream.write(expected.getBytes("UTF-8"));
                return null;
            }
        };
        doAnswer(answer).when(key).writeTo(any(OutputStream.class));

        // when
        manager.putSecretValue("secret", "version", key, PREVIOUS);

        // then
        final PutSecretValueRequest request = new PutSecretValueRequest();
        request.setSecretId("secret");
        request.setClientRequestToken("version");
        request.setVersionStages(singleton("AWSPREVIOUS"));
        request.setSecretBinary(ByteBuffer.wrap(expected.getBytes("UTF-8")));
        verify(delegate).putSecretValue(eq(request));
    }

    @Test
    public final void verifyPutSecretValueStoresKeys() throws IOException {
        // given
        final String expected = "expected";
        final Key key0 = mock(Key.class);
        final Key key1 = mock(Key.class);
        final Answer<?> answer = new Answer<Void>() {
            public Void answer(final InvocationOnMock invocation) throws Throwable {
                final OutputStream stream = invocation.getArgument(0);
                stream.write(expected.getBytes("UTF-8"));
                return null;
            }
        };
        doAnswer(answer).when(key0).writeTo(any(OutputStream.class));
        doAnswer(answer).when(key1).writeTo(any(OutputStream.class));

        // when
        manager.putSecretValue("secret", "version", asList(key0, key1), PREVIOUS);

        // then
        final PutSecretValueRequest request = new PutSecretValueRequest();
        request.setSecretId("secret");
        request.setClientRequestToken("version");
        request.setVersionStages(singleton("AWSPREVIOUS"));
        request.setSecretBinary(ByteBuffer.wrap((expected + expected).getBytes("UTF-8")));
        verify(delegate).putSecretValue(eq(request));
    }

}