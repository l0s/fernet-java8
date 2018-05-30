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

import static java.util.Collections.*;
import static com.macasaet.fernet.aws.secretsmanager.rotation.Step.*;
import static org.mockito.BDDMockito.*;
import static org.mockito.MockitoAnnotations.*;
import static org.junit.Assert.*;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.Mock;
import org.mockito.Spy;

import com.amazonaws.services.kms.AWSKMS;
import com.amazonaws.services.kms.model.GenerateRandomRequest;
import com.amazonaws.services.kms.model.GenerateRandomResult;
import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.secretsmanager.model.ResourceNotFoundException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.module.jaxb.JaxbAnnotationModule;

/**
 * <p>Copyright &copy; 2018 Carlos Macasaet.</p>
 * @author Carlos Macasaet
 */
public class AbstractFernetKeyRotatorTest {

    @Spy
    private ObjectMapper mapper = new ObjectMapper().registerModule(new JaxbAnnotationModule());
    @Mock
    private SecretsManager secretsManager;
    @Mock
    private AWSKMS kms;
    @Spy
    private SecureRandom random;

    private AbstractFernetKeyRotator rotator;

    @Rule
    public ExpectedException thrown = ExpectedException.none();
    @Captor
    private ArgumentCaptor<RotationRequest> requestCaptor;

    @Before
    public void setUp() throws Exception {
        initMocks(this);
        rotator = new AbstractFernetKeyRotator(mapper, secretsManager, kms, random) {
            protected void testSecret(String secretId, String clientRequestToken) {
            }

            protected void createSecret(String secretId, String clientRequestToken) {
            }
        };
        rotator = spy(rotator);
    }

    @After
    public void tearDown() throws Exception {
    }

    @Test
    public final void verifyHandleRequestDeserialisesRequest() throws IOException {
        // given
        final Context context = mock(Context.class);
        final String inputString = "{"
          + "\"SecretId\": \"secret\","
          + "\"ClientRequestToken\": \"token\","
          + "\"Step\": \"setSecret\""
          + "}";
        doNothing().when(rotator).seed();
        doNothing().when(rotator).handleRotationRequest(any(RotationRequest.class));

        try (ByteArrayInputStream input = new ByteArrayInputStream(inputString.getBytes("UTF-8"))) {
            try (ByteArrayOutputStream output = new ByteArrayOutputStream()) {
                // when
                rotator.handleRequest(input, output, context);

                // then
                verify(rotator).handleRotationRequest(requestCaptor.capture());
                final RotationRequest result = requestCaptor.getValue();
                assertEquals("secret", result.getSecretId());
                assertEquals("token", result.getClientRequestToken());
                assertEquals(SET_SECRET, result.getStep());
            }
        }
    }

    @Test
    public final void verifyHandleRequestSeedsRandomNumberGenerator() throws IOException {
        // given
        final Context context = mock(Context.class);
        final String inputString = "{"
          + "\"SecretId\": \"secret\","
          + "\"ClientRequestToken\": \"token\","
          + "\"Step\": \"setSecret\""
          + "}";
        doNothing().when(rotator).handleRotationRequest(any(RotationRequest.class));
        doNothing().when(rotator).seed();

        try (ByteArrayInputStream input = new ByteArrayInputStream(inputString.getBytes("UTF-8"))) {
            try (ByteArrayOutputStream output = new ByteArrayOutputStream()) {
                // when
                rotator.handleRequest(input, output, context);

                // then
                verify(rotator).seed();
            }
        }
    }

    @Test
    public final void verifyConditionallyCreateSecretSkipsCreation() throws UnsupportedEncodingException {
        // given
        given(secretsManager.getSecretVersion("secret", "version")).willReturn(ByteBuffer.wrap("key".getBytes("UTF-8")));

        // when
        rotator.conditionallyCreateSecret("secret", "version");

        // then
        verify(rotator, never()).createSecret("secret", "version");
    }

    @Test
    public final void verifyConditionallyCreateCreatesSecret() throws UnsupportedEncodingException {
        // given
        given(secretsManager.getSecretVersion("secret", "version")).willThrow(new ResourceNotFoundException("not found"));

        // when
        rotator.conditionallyCreateSecret("secret", "version");

        // then
        verify(rotator).createSecret("secret", "version");
    }

    @Test
    public final void verifyFinishSecretDoesNothing() {
        // given
        final Map<String, List<String>> versions = new HashMap<>();
        versions.put("version", singletonList("AWSCURRENT"));

        // when
        rotator.finishSecret("secret", "version", versions);

        // then
        verifyNoMoreInteractions(secretsManager);
    }

    @Test
    public final void verifyFinishSecretFails() {
        // given
        final Map<String, List<String>> versions = new HashMap<>();
        versions.put("version", singletonList("AWSPENDING"));

        // when
        thrown.expect(RuntimeException.class);
        rotator.finishSecret("secret", "version", versions);

        // then (exception thrown)
    }

    @Test
    public final void verifyFinishSecretRotatesSecret() {
        // given
        final Map<String, List<String>> versions = new HashMap<>();
        versions.put("newVersion", singletonList("AWSPENDING"));
        versions.put("oldVersion", singletonList("AWSCURRENT"));

        // when
        rotator.finishSecret("secret", "newVersion", versions);

        // then
        verify(secretsManager).rotateSecret("secret", "newVersion", "oldVersion");
    }

    @Test
    public final void verifySeedOnlyRunsOnce() {
        // given
        final GenerateRandomResult randomResult = new GenerateRandomResult();
        final byte[] bytes = new byte[512];
        Arrays.fill(bytes, (byte)17);
        randomResult.setPlaintext(ByteBuffer.wrap(bytes));
        given(kms.generateRandom(any(GenerateRandomRequest.class))).willReturn(randomResult);

        // when
        rotator.seed();
        rotator.seed();

        // then
        verify(random, times(1)).setSeed(bytes);
    }

}