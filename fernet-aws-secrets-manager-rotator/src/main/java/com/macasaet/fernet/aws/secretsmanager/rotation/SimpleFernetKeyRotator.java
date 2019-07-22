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

import static com.macasaet.fernet.aws.secretsmanager.rotation.Stage.PENDING;

import java.nio.ByteBuffer;
import java.security.SecureRandom;

import com.amazonaws.services.kms.AWSKMS;
import com.amazonaws.services.kms.AWSKMSClientBuilder;
import com.amazonaws.services.secretsmanager.AWSSecretsManagerClientBuilder;
import com.macasaet.fernet.Key;

/**
 * <p>AWS Lambda that rotates Fernet keys. To access a key, retrieve AWSCURRENT, AWSPENDING, or AWSPREVIOUS. To validate
 * and decrypt a token, it will be necessary to retrieve AWSCURRENT and AWSPREVIOUS as there is no way to know which one
 * was used to generate the token.</p>
 * 
 * <p>Grant AWS Secrets Manager permission to execute the Lambda using this:</p>
 * <pre>aws lambda add-permission --function-name arn:aws:lambda:{region}:{accountId}:function:{functionName} --principal secretsmanager.amazonaws.com --action lambda:InvokeFunction --statement-id SecretsManagerAccess</pre>
 *
 * <p>Copyright &copy; 2018 Carlos Macasaet.</p>
 * @author Carlos Macasaet
 */
@SuppressWarnings("PMD.LawOfDemeter")
public class SimpleFernetKeyRotator extends AbstractFernetKeyRotator {

    private static final int fernetKeySize = 32;

    protected SimpleFernetKeyRotator(final SecretsManager secretsManager, final AWSKMS kms, final SecureRandom random) {
        super(secretsManager, kms, random);
    }

    protected SimpleFernetKeyRotator(final SecureRandom random) {
        this(new SecretsManager(AWSSecretsManagerClientBuilder.standard()
                .withRequestHandlers(new MemoryOverwritingRequestHandler(random)).build()),
                AWSKMSClientBuilder.defaultClient(), random);
    }

    public SimpleFernetKeyRotator() {
        this(new SecureRandom());
    }

    protected void createSecret(final String secretId, final String clientRequestToken) {
        final Key key = Key.generateKey(getRandom());
        getSecretsManager().putSecretValue(secretId, clientRequestToken, key, PENDING);
        getLogger().info("createSecret: Successfully put secret for ARN {} and version {}.", secretId, clientRequestToken);
    }

    protected void testSecret(final String secretId, final String clientRequestToken) {
        final ByteBuffer buffer = getSecretsManager().getSecretVersion(secretId, clientRequestToken);
        try {
            if (buffer.remaining() != fernetKeySize) {
                throw new IllegalStateException("Fernet key must be exactly " + fernetKeySize + " bytes");
            }
            final byte[] signingKey = new byte[16];
            buffer.get(signingKey);
            final byte[] encryptionKey = new byte[16];
            buffer.get(encryptionKey);
            if (buffer.hasRemaining()) {
                throw new IllegalStateException("Encountered extra bytes.");
            }
            new Key(signingKey, encryptionKey);
            wipe(signingKey);
            wipe(encryptionKey);
        } finally {
            wipe(buffer);
        }
        getLogger().info("testSecret: Successfully validated Fernet Key for ARN {} and version {}.", secretId, clientRequestToken);
    }

}