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

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;

import com.amazonaws.services.kms.AWSKMS;
import com.amazonaws.services.kms.AWSKMSClientBuilder;
import com.amazonaws.services.secretsmanager.AWSSecretsManagerClientBuilder;
import com.amazonaws.services.secretsmanager.model.GetSecretValueResult;
import com.amazonaws.services.secretsmanager.model.ResourceNotFoundException;
import com.macasaet.fernet.Key;
import com.macasaet.fernet.StringValidator;
import com.macasaet.fernet.Token;
import com.macasaet.fernet.Validator;

/**
 * This rotator can be used when an array of Fernet keys is stored in AWSCURRENT. 
 *
 * <p>Copyright &copy; 2018 Carlos Macasaet.</p>
 * @author Carlos Macasaet
 */
public class MultiFernetKeyRotator extends AbstractFernetKeyRotator {

    private static final Validator<String> validator = new StringValidator() {
    };
    private int maxActiveKeys = 3;

    protected MultiFernetKeyRotator(final SecretsManager secretsManager, final AWSKMS kms,
            final SecureRandom random) {
        super(secretsManager, kms, random);
    }

    public MultiFernetKeyRotator() {
        this(new SecretsManager(AWSSecretsManagerClientBuilder.defaultClient()), AWSKMSClientBuilder.defaultClient(),
                new SecureRandom());
        // TODO retrieve max active keys from system property
    }

    protected void testSecret(final String secretId, final String clientRequestToken) {
        final GetSecretValueResult pendingSecretResult = getSecretsManager().getSecretVersionStage(secretId,
                clientRequestToken, PENDING);
        final String string = pendingSecretResult.getSecretString();
        final byte[] bytes = Base64.getUrlDecoder().decode(string);
        if (bytes.length % 32 != 0) {
            throw new IllegalStateException("There must be a multiple of 32 bytes.");
        }
        // first key will become the staged key
        final Key candidateStagedKey = new Key(Arrays.copyOfRange(bytes, 0, 32)) {
        }; // TODO: this constructor should probably be public
        Token.generate(getRandom(), candidateStagedKey, "").validateAndDecrypt(candidateStagedKey, validator);
    }

    protected void createSecret(final String secretId, final String clientRequestToken) {
        getSecretsManager().assertCurrentStageExists(secretId);
        try {
            getSecretsManager().getSecretVersionStage(secretId, clientRequestToken, PENDING);
            getLogger().warn("createSecret: Successfully retrieved secret for {}. Doing nothing.", secretId);
        } catch (final ResourceNotFoundException rnfe) {
            final GetSecretValueResult current = getSecretsManager().getSecretVersionStage(secretId, clientRequestToken,
                    CURRENT);
            final String currentActiveKeysBase64 = current.getSecretString();
            final byte[] currentActiveKeyBytes = Base64.getUrlDecoder().decode(currentActiveKeysBase64);
            if (currentActiveKeyBytes.length % 32 != 0) {
                throw new IllegalStateException("There must be a multiple of 32 bytes.");
            }
            final int numKeys = currentActiveKeyBytes.length / 32;
            List<Key> keys = new ArrayList<>(numKeys + 1);
            for( int i = 0; i < currentActiveKeyBytes.length; i += 32 ) {
                final Key key = new Key(Arrays.copyOfRange(currentActiveKeyBytes, i, i + 32) ) {};
                keys.add(key);
            }
            // TODO currently no way to inject a key generator
            final Key keyToStage = Key.generateKey(getRandom());
            keys.add(0, keyToStage);
            if( keys.size() > getMaxActiveKeys() ) {
                keys = keys.subList(0, getMaxActiveKeys());
            }

            getSecretsManager().putSecretValue(secretId, clientRequestToken, keys, PENDING);
            getLogger().info("createSecret: Successfully put secret for ARN {} and version {}.", secretId,
                    clientRequestToken);
        }
    }

    protected int getMaxActiveKeys() {
        return maxActiveKeys;
    }

    protected void setMaxActiveKeys(int maxActiveKeys) {
        this.maxActiveKeys = maxActiveKeys;
    }

}