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

import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;

import com.amazonaws.services.kms.AWSKMS;
import com.amazonaws.services.kms.AWSKMSClientBuilder;
import com.amazonaws.services.secretsmanager.AWSSecretsManagerClientBuilder;
import com.macasaet.fernet.Key;

/**
 * <p>This rotator can be used when an array of Fernet keys is stored in AWSCURRENT.</p> 
 *
 * <p>Grant AWS Secrets Manager permission to execute the Lambda using this:</p>
 * <pre>aws lambda add-permission --function-name arn:aws:lambda:{region}:{accountId}:function:{functionName} --principal secretsmanager.amazonaws.com --action lambda:InvokeFunction --statement-id SecretsManagerAccess</pre>
 *
 * <p>Copyright &copy; 2018 Carlos Macasaet.</p>
 * @author Carlos Macasaet
 */
@SuppressWarnings("PMD.LawOfDemeter")
public class MultiFernetKeyRotator extends AbstractFernetKeyRotator {

    private static final int fernetKeySize = 32;
    private int maxActiveKeys = 3;

    /**
     * @param secretsManager a utility for interacting with AWS Secrets Manager
     * @param kms a KMS client for seeding the random number generator
     * @param random an entropy source
     */
    protected MultiFernetKeyRotator(final SecretsManager secretsManager, final AWSKMS kms, final SecureRandom random) {
        super(secretsManager, kms, random);
        final String maxActiveKeysString = System.getenv("MAX_ACTIVE_KEYS");
        if (maxActiveKeysString != null && !"".equals(maxActiveKeysString)) {
            setMaxActiveKeys(Integer.parseInt(maxActiveKeysString));
        }
    }

    /**
     * @param random an entropy source
     */
    protected MultiFernetKeyRotator(final SecureRandom random) {
        this(new SecretsManager(AWSSecretsManagerClientBuilder.standard()
                .withRequestHandlers(new MemoryOverwritingRequestHandler(random)).build()),
                AWSKMSClientBuilder.defaultClient(), random);
    }

    public MultiFernetKeyRotator() {
        this(new SecureRandom());
    }

    @SuppressWarnings("PMD.AvoidInstantiatingObjectsInLoops")
    protected void createSecret(final String secretId, final String clientRequestToken) {
        final ByteBuffer currentSecret = getSecretsManager().getSecretStage(secretId, CURRENT);
        try {
            if (currentSecret.remaining() % fernetKeySize != 0) {
                throw new IllegalStateException("There must be a multiple of 32 bytes.");
            }
            final int numKeys = currentSecret.remaining() / fernetKeySize;
            List<Key> keys = new ArrayList<>(numKeys + 1);
            while (currentSecret.hasRemaining()) {
                final byte[] signingKey = new byte[16];
                currentSecret.get(signingKey);
                final byte[] encryptionKey = new byte[16];
                currentSecret.get(encryptionKey);
                final Key key = new Key(signingKey, encryptionKey);
                keys.add(key);
                wipe(signingKey);
                wipe(encryptionKey);
            }
            final Key keyToStage = Key.generateKey(getRandom());
            keys.add(0, keyToStage);
            final int desiredSize = getMaxActiveKeys() + 1; // max active keys + one pending
            if (keys.size() > desiredSize) {
                keys = keys.subList(0, desiredSize);
            }

            getSecretsManager().putSecretValue(secretId, clientRequestToken, keys, PENDING);
        } finally {
            wipe(currentSecret);
        }
        getLogger().info("createSecret: Successfully put secret for ARN {} and version {}.", secretId,
                clientRequestToken);
    }

    protected void testSecret(final String secretId, final String clientRequestToken) { 
        final ByteBuffer currentSecret = getSecretsManager().getSecretVersion(secretId,
                clientRequestToken);
        try {
            if (currentSecret.remaining() % fernetKeySize != 0) {
                throw new IllegalStateException("There must be a multiple of " + fernetKeySize + " bytes.");
            }
            // first key will become the staged key
            final byte[] signingKey = new byte[16];
            currentSecret.get(signingKey);
            final byte[] encryptionKey = new byte[16];
            currentSecret.get(encryptionKey);
            new Key(signingKey, encryptionKey);
            wipe(signingKey);
            wipe(encryptionKey);
        } finally {
            wipe(currentSecret);
        }
    }

    /**
     * @return the total number of keys that can be used for decryption. The actual number of keys stored will be this value plus one.
     */
    protected int getMaxActiveKeys() {
        return maxActiveKeys;
    }

    /**
     * @param maxActiveKeys the total number of keys that can be used for decryption. The actual number of keys stored will be this value plus one.
     */
    @SuppressWarnings("PMD.AvoidLiteralsInIfCondition")
    protected void setMaxActiveKeys(final int maxActiveKeys) {
        getLogger().info("Setting the maximum number of active keys to: {}.", maxActiveKeys);
        if (maxActiveKeys < 1) {
            throw new IllegalArgumentException("The maximum number of active keys must be at least 1.");
        }
        this.maxActiveKeys = maxActiveKeys;
    }

}