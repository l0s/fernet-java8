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

import static com.macasaet.fernet.aws.secretsmanager.rotation.Stage.CURRENT;
import static com.macasaet.fernet.aws.secretsmanager.rotation.Stage.PENDING;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.Buffer;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.concurrent.atomic.AtomicBoolean;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import com.amazonaws.services.kms.AWSKMS;
import com.amazonaws.services.kms.model.GenerateRandomRequest;
import com.amazonaws.services.kms.model.GenerateRandomResult;
import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestStreamHandler;
import com.amazonaws.services.secretsmanager.model.DescribeSecretResult;
import com.amazonaws.services.secretsmanager.model.ResourceNotFoundException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.module.jaxb.JaxbAnnotationModule;

/**
 * This is an AWS Lambda {@link RequestStreamHandler} that rotates a Fernet key.
 *
 * <p>Copyright &copy; 2018 Carlos Macasaet.</p>
 * @author Carlos Macasaet
 */
@SuppressWarnings({"PMD.LawOfDemeter", "PMD.BeanMembersShouldSerialize", "PMD.TooManyMethods"})
abstract class AbstractFernetKeyRotator implements RequestStreamHandler {

    private final Logger logger = LogManager.getLogger(getClass());

    private final ObjectMapper mapper;
    private final SecretsManager secretsManager;
    private final AWSKMS kms;
    private final SecureRandom random;

    private final AtomicBoolean seeded = new AtomicBoolean(false);

    protected AbstractFernetKeyRotator(final SecretsManager secretsManager, final AWSKMS kms,
            final SecureRandom random) {
        this(new ObjectMapper().registerModule(new JaxbAnnotationModule()), secretsManager, kms, random);
    }

    protected AbstractFernetKeyRotator(final ObjectMapper mapper, final SecretsManager secretsManager, final AWSKMS kms,
            final SecureRandom random) {
        if (mapper == null) {
            throw new IllegalArgumentException("mapper cannot be null");
        }
        if (secretsManager == null) {
            throw new IllegalArgumentException("secretsManager cannot be null");
        }
        if (kms == null) {
            throw new IllegalArgumentException("kms cannot be null");
        }
        if (random == null) {
            throw new IllegalArgumentException("random cannot be null");
        }
        this.mapper = mapper;
        this.secretsManager = secretsManager;
        this.kms = kms;
        this.random = random;
    }

    public void handleRequest(final InputStream input, final OutputStream output, final Context context) throws IOException {
        final RotationRequest request = getMapper().readValue(input, RotationRequest.class);
        getLogger().debug("Processing request: {}", request);

        handleRotationRequest(request);
    }

    protected void finalize() throws Throwable {
        getKms().shutdown();
        getSecretsManager().shutdown();

        super.finalize();
    }

    protected void handleRotationRequest(final RotationRequest request) {
        final String secretId = request.getSecretId();
        final Map<String, List<String>> versions = getAndValidateVersions(secretId);
        final String clientRequestToken = getAndValidateClientRequestToken(request, secretId, versions);

        final List<String> stages = versions.get(clientRequestToken);
        if (stages.contains(CURRENT.getAwsName())) {
            getLogger().warn("Secret version {} already set as AWSCURRENT for secret {}. Doing nothing.",
                    clientRequestToken, secretId);
            return;
        } else if (!stages.contains(PENDING.getAwsName())) {
            throw new IllegalArgumentException("Secret version " + clientRequestToken
                    + " not set as AWSPENDING for rotation of secret " + secretId + ".");
        }
        switch (request.getStep()) {
            case CREATE_SECRET:
                conditionallyCreateSecret(secretId, clientRequestToken);
                return;
            case FINISH_SECRET:
                finishSecret(secretId, clientRequestToken, versions);
                return;
            case SET_SECRET:
                // not applicable
                return;
            case TEST_SECRET:
                testSecret(secretId, clientRequestToken);
                return;
            default:
                throw new IllegalArgumentException("Missing or invalid step provided");
        }
    }

    protected Map<String, List<String>> getAndValidateVersions(final String secretId) {
        final DescribeSecretResult secretMetadata = getSecretsManager().describeSecret(secretId);
        if (secretMetadata.isRotationEnabled() == null || !secretMetadata.isRotationEnabled()) {
            throw new IllegalArgumentException("Secret " + secretId + " is not enabled for rotation.");
        }
        return secretMetadata.getVersionIdsToStages();
    }

    protected String getAndValidateClientRequestToken(final RotationRequest request, final String secretId,
            final Map<String, List<String>> versions) {
        final String retval = request.getClientRequestToken();
        if (!versions.containsKey(retval)) {
            throw new IllegalArgumentException("Secret version " + retval
                    + " has no stage for rotation of secret " + secretId + ".");
        }
        return retval;
    }

    protected void conditionallyCreateSecret(final String secretId, final String clientRequestToken) {
        getSecretsManager().assertCurrentStageExists(secretId);
        try {
            getSecretsManager().getSecretVersion(secretId, clientRequestToken);
            getLogger().warn("createSecret: Successfully retrieved secret for {}. Doing nothing.", secretId);
        } catch (final ResourceNotFoundException rnfe) {
            createSecret(secretId, clientRequestToken);
        }
    }

    /**
     * Create a Fernet key secret and store it in AWS Secrets Manager with the stage "AWSPENDING". If there is already an
     * "AWSPENDING" secret, then do nothing.
     *
     * @param secretId the ARN of the secret. e.g. arn:aws:secretsmanager:{region}:{account}:secret:{secret-name}
     * @param clientRequestToken a unique identifier for this rotation request
     */
    protected abstract void createSecret(String secretId, String clientRequestToken);

    /**
     * Validate the Fernet key secret generated by {@link #createSecret(String, String)}. Throw an exception if there is
     * a problem with the secret that would make it unusable.
     *
     * @param secretId
     *            the ARN of the secret. e.g. arn:aws:secretsmanager:{region}:{account}:secret:{secret-name}
     * @param clientRequestToken
     *            a unique identifier for this rotation request
     */
    protected abstract void testSecret(String secretId, String clientRequestToken);

    @SuppressWarnings("PMD.DataflowAnomalyAnalysis")
    protected void finishSecret(final String secretId, final String clientRequestToken,
            final Map<String, List<String>> versions) {
        final Entry<? extends String, ?> currentEntry = versions.entrySet().stream().filter(entry -> {
            final Collection<? extends String> versionStages = entry.getValue();
            return versionStages.contains(CURRENT.getAwsName() );
        }).findFirst().orElseThrow(() -> new IllegalStateException("No AWSCURRENT secret set for " + secretId + "."));
        final String currentVersion = currentEntry.getKey();
        if (currentVersion.equalsIgnoreCase(clientRequestToken)) {
            // The correct version is already marked as current, return
            getLogger().warn("finishSecret: Version {} already marked as AWSCURRENT for {}", currentVersion,
                    secretId);
            return;
        }

        getSecretsManager().rotateSecret(secretId, clientRequestToken, currentVersion);
        getLogger().info("finishSecret: Successfully set AWSCURRENT stage to version {} for secret {}.",
                clientRequestToken, secretId);
    }

    /**
     * This seeds the random number generator using KMS if and only it hasn't already been seeded.
     * 
     * This requires the permission: <code>kms:GenerateRandom</code>
     */
    protected void seed() {
        if (!seeded.get()) {
            synchronized (random) {
                if (!seeded.get()) {
                    getLogger().debug("Seeding random number generator");
                    final GenerateRandomRequest request = new GenerateRandomRequest();
                    request.setNumberOfBytes(512);
                    final GenerateRandomResult result = getKms().generateRandom(request);
                    final ByteBuffer randomBytes = result.getPlaintext();
                    final byte[] bytes = new byte[randomBytes.remaining()];
                    randomBytes.get(bytes);
                    random.setSeed(bytes);
                    seeded.set(true);
                    getLogger().debug("Seeded random number generator");
                }
            }
        }
    }

    /**
     * Overwrite the data in the byte array prior to returning memory to the system.
     *
     * @param secretBytes secret data that is no longer needed
     */
    protected void wipe(final byte[] secretBytes) {
        getRandom().nextBytes(secretBytes);
    }

    /**
     * Overwrite the data in the byte buffer prior to returning memory to the system.
     *
     * @param secret secret data that is no longer needed
     */
    protected void wipe(final ByteBuffer secret) {
        ((Buffer)secret).clear();
        final byte[] random = new byte[secret.capacity()];
        getRandom().nextBytes(random);
        secret.put(random);
    }

    protected SecretsManager getSecretsManager() {
        return secretsManager;
    }

    protected AWSKMS getKms() {
        return kms;
    }

    protected SecureRandom getRandom() {
        seed();
        return random;
    }

    protected Logger getLogger() {
        return logger;
    }

    protected ObjectMapper getMapper() {
        return mapper;
    }

}