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
package com.macasaet.fernet.jersey;

import static java.util.Collections.singleton;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.MockitoAnnotations.openMocks;

import java.util.Collection;
import java.util.function.Function;
import java.util.function.Supplier;

import javax.ws.rs.NotAuthorizedException;

import org.glassfish.jersey.server.ContainerRequest;
import org.glassfish.jersey.server.model.Parameter;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;

import com.macasaet.fernet.Key;
import com.macasaet.fernet.Token;
import com.macasaet.fernet.Validator;
import com.macasaet.fernet.jaxrs.FernetSecret;

public class FernetSecretValueParamProviderTest {

    private AutoCloseable mockContext;

    @Mock
    private Validator<String> validator;
    @Mock
    private Supplier<Collection<Key>> keySupplier;
    @Mock
    private TokenHeaderUtility tokenHeaderUtility;

    @InjectMocks
    private FernetSecretValueParamProvider<String> provider;

    @Mock
    private Parameter parameter;
    @Mock
    private Key key;
    @Mock
    private Token token;
    
    private Collection<Key> keys;

    private Function<ContainerRequest, String> function;

    @Before
    public void setUp() {
        mockContext = openMocks(this); // there seems to be a bug with @RunWith(MockitoJUnitRunner.class)
        given(parameter.isAnnotationPresent(FernetSecret.class)).willReturn(true);
        function = provider.getValueProvider(parameter);

        keys = singleton(key);
        given(keySupplier.get()).willReturn(keys);
    }

    @After
    public void tearDown() throws Exception {
        mockContext.close();
    }

    @Test
    public final void verifyApplyReturnsPayloadFromBearerToken() {
        // given
        final ContainerRequest request = mock(ContainerRequest.class);
        given(tokenHeaderUtility.getAuthorizationToken(request)).willReturn(token);
        given(validator.validateAndDecrypt(keys, token)).willReturn("hello");

        // when
        final String result = function.apply(request);

        // then
        assertEquals("hello", result);
    }

    @Test
    public final void verifyApplyReturnsPayloadFromXToken() {
        // given
        final ContainerRequest request = mock(ContainerRequest.class);
        given(tokenHeaderUtility.getXAuthorizationToken(request)).willReturn(token);
        given(validator.validateAndDecrypt(keys, token)).willReturn("hello");

        // when
        final String result = function.apply(request);

        // then
        assertEquals("hello", result);
    }

    @Test
    public final void verifyApplyThrowsNotAuthorized() {
        // given
        final ContainerRequest request = mock(ContainerRequest.class);

        // when / then
        assertThrows(NotAuthorizedException.class, () -> function.apply(request));
    }

}