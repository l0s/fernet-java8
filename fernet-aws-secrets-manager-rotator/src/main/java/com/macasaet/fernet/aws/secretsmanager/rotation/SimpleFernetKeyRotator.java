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
import com.amazonaws.services.secretsmanager.model.GetSecretValueResult;
import com.macasaet.fernet.Key;
import com.macasaet.fernet.Token;

/**
 * <p>AWS Lambda that rotates Fernet keys. To access a key, retrieve AWSCURRENT, AWSPENDING, or AWSPREVIOUS. To validate
 * and decrypt a token, it will be necessary to retrieve AWSCURRENT and AWSPREVIOUS as there is no way to know which one
 * was used to generate the token.</p>
 * 
 * <p>Grant AWS Secrets Manager permission to execute the Lambda using this:<br />
 * <pre>aws lambda add-permission --function-name arn:aws:lambda:{region}:{accountId}:function:{functionName} --principal secretsmanager.amazonaws.com --action lambda:InvokeFunction --statement-id SecretsManagerAccess</pre></p>
 *
 * <p>Copyright &copy; 2018 Carlos Macasaet.</p>
 * @author Carlos Macasaet
 */
public class SimpleFernetKeyRotator extends AbstractFernetKeyRotator {

    protected SimpleFernetKeyRotator(final SecretsManager secretsManager, final AWSKMS kms, final SecureRandom random) {
        super(secretsManager, kms, random);
    }

    public SimpleFernetKeyRotator() {
        this(new SecretsManager(AWSSecretsManagerClientBuilder.defaultClient()), AWSKMSClientBuilder.defaultClient(),
                new SecureRandom());
    }

    protected void createSecret(final String secretId, final String clientRequestToken) {
        // TODO: there is currently no way to inject a Key generator
        final Key key = Key.generateKey(getRandom());
        getSecretsManager().putSecretValue(secretId, clientRequestToken, key, PENDING);
        getLogger().info("createSecret: Successfully put secret for ARN {} and version {}.", secretId, clientRequestToken);
    }

    protected void testSecret(final String secretId, final String clientRequestToken) {
        final GetSecretValueResult pendingSecretResult = getSecretsManager().getSecretVersion(secretId, clientRequestToken,
                PENDING);
        final ByteBuffer buffer = pendingSecretResult.getSecretBinary();
        final byte[] signingKey = new byte[16];
        buffer.get(signingKey);
        final byte[] encryptionKey = new byte[16];
        buffer.get(encryptionKey);
        final Key key = new Key(signingKey, encryptionKey);
        final Token token = Token.generate(getRandom(), key, "");
        if (!token.isValidSignature(key)) {
            throw new IllegalStateException("Pending key is unable to create and validate a Fernet token.");
        }
        getLogger().info("testSecret: Successfully validated Fernet Key for ARN {} and version {}.", secretId, clientRequestToken);
    }

}