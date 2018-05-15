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
package com.macasaet.fernet.aws.secretsmanager.rotation;

import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.List;
import java.util.Map;
import java.util.Random;

import com.amazonaws.services.kms.AWSKMS;
import com.amazonaws.services.kms.model.GenerateRandomRequest;
import com.amazonaws.services.kms.model.GenerateRandomResult;
import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.LambdaLogger;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.secretsmanager.model.DescribeSecretResult;

abstract class AbstractFernetKeyRotator implements RequestHandler<Request, Void> {

    private final SecretsManager secretsManager;
    private final AWSKMS kms;
    private final SecureRandom random;

    transient volatile boolean seeded = false;

    protected AbstractFernetKeyRotator(final SecretsManager secretsManager, final AWSKMS kms,
            final SecureRandom random) {
        if (secretsManager == null) {
            throw new IllegalArgumentException("secretsManager cannot be null");
        }
        if (kms == null) {
            throw new IllegalArgumentException("kms cannot be null");
        }
        if (random == null) {
            throw new IllegalArgumentException("random cannot be null");
        }
        this.secretsManager = secretsManager;
        this.kms = kms;
        this.random = random;
    }

    public Void handleRequest(final Request request, final Context context) {
        seed();

        final LambdaLogger logger = context.getLogger();
        final String secretId = request.getSecretId();
        final String clientRequestToken = request.getClientRequestToken();

        final DescribeSecretResult secretMetadata = getSecretsManager().describeSecret(secretId);
        if (secretMetadata.isRotationEnabled() == null || !secretMetadata.isRotationEnabled()) {
            throw new IllegalArgumentException("Secret " + secretId + " is not enabled for rotation.");
        }
        final Map<String, List<String>> versions = secretMetadata.getVersionIdsToStages();

        if (!versions.containsKey(clientRequestToken)) {
            throw new IllegalArgumentException("Secret version " + clientRequestToken
                    + " has no stage for rotation of secret " + secretId + ".");
        }

        final List<String> stages = versions.get(clientRequestToken);
        if (stages.contains("AWSCURRENT")) {
            logger.log("Secret version " + clientRequestToken
                    + " already set as AWSCURRENT for secret " + secretId + ". Doing nothing.");
            return null;
        } else if (!stages.contains("AWSPENDING")) {
            throw new IllegalArgumentException("Secret version " + clientRequestToken
                    + " not set as AWSPENDING for rotation of secret " + secretId + ".");
        }
        switch (request.getStep()) {
            case CREATE_SECRET:
                createSecret(logger, secretId, clientRequestToken);
                return null;
            case FINISH_SECRET:
                String currentVersion = null;
                for( final String versionId : versions.keySet() ) {
                    final List<String> versionStages = versions.get(versionId);
                    if( versionStages.contains("AWSCURRENT") ) {
                        if( versionId.equals(clientRequestToken ) ) {
                            // The correct version is already marked as current, return
                            logger.log("finishSecret: Version " + versionId
                    + " already marked as AWSCURRENT for " + secretId + "");
                            return null;
                        }
                        currentVersion = versionId;
                        break;
                    }
                }
                if (currentVersion == null) {
                    throw new IllegalStateException("No AWSCURRENT secret set for " + secretId + ".");
                }
                getSecretsManager().updateSecretVersionStage(secretId, clientRequestToken, currentVersion);
                logger.log("finishSecret: Successfully set AWSCURRENT stage to version " + clientRequestToken
                        + " for secret " + secretId + ".");
                return null;
            case SET_SECRET:
                // not applicable
                return null;
            case TEST_SECRET:
                testSecret(secretId, clientRequestToken);
                return null;
            default:
                throw new IllegalArgumentException("Missing or invalid step provided");
        }
    }

    protected abstract void testSecret(String secretId, String clientRequestToken);

    protected abstract void createSecret(LambdaLogger logger, String secretId, String clientRequestToken);

    protected void seed() {
        if (!seeded) {
            synchronized (random) {
                if (!seeded) {
                    final byte[] bytes = new byte[512];
                    final GenerateRandomRequest request = new GenerateRandomRequest();
                    request.setNumberOfBytes(bytes.length);
                    final GenerateRandomResult result = kms.generateRandom(request);
                    final ByteBuffer randomBytes = result.getPlaintext();
                    randomBytes.get(bytes);
                    random.setSeed(bytes);
                    seeded = true;
                }
            }
        }
    }

    protected Random getRandom() {
        return random;
    }

    protected SecretsManager getSecretsManager() {
        return secretsManager;
    }

}