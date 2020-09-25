# AWS Secrets Manager Fernet Key Rotator Lambda

[![Javadocs](https://javadoc.io/badge/com.macasaet.fernet/fernet-aws-secrets-manager-rotator.svg)](https://javadoc.io/doc/com.macasaet.fernet/fernet-aws-secrets-manager-rotator)
[![Known Vulnerabilities](https://snyk.io/test/github/l0s/fernet-java8/badge.svg?targetFile=fernet-aws-secrets-manager-rotator/pom.xml)](https://snyk.io/test/github/l0s/fernet-java8?targetFile=fernet-aws-secrets-manager-rotator/pom.xml)

This module provides two schemes for storing Fernet secret keys in AWS
Secrets Manager, "Simple" and "Multi".

The Simple scheme stores a single key in the Secret. The current active key
is tagged with the stage "AWSCURRENT". This key can be used for both
encryption (Fernet token generation) as well as decryption (Fernet token
validation). The previously active key is tagged with the stage
"AWSPREVIOUS". It should only be used for decryption.

The Multi scheme stores multiple Fernet keys in the Secret. The first
key is the staged key and should not be used. The second key is the
current active key. It can be used for both encryption and decryption.
The third and all following keys are previously active keys. They should
only be used for Fernet token validation or decryption. This is the same
key rotation mechanism used by
[OpenStack](https://redhatstackblog.redhat.com/2017/12/20/using-ansible-for-fernet-key-rotation-on-red-hat-openstack-platform-11/).

## Creating The Secret

To get started, generate the initial secret value or values. To generate a
Simple Secret, run the
[CreateSimpleKey](https://github.com/l0s/fernet-java8/blob/master/fernet-aws-secrets-manager-rotator/src/test/java/com/macasaet/fernet/aws/secretsmanager/bootstrap/CreateSimpleKey.java)
class. To generate a Multi Secret, run the
[CreateMultiKey](https://github.com/l0s/fernet-java8/blob/master/fernet-aws-secrets-manager-rotator/src/test/java/com/macasaet/fernet/aws/secretsmanager/bootstrap/CreateMultiKey.java)
class. These will generate random keys and store them in a local file
(called either "simple-key" or "multi-key"). To create the Secret with
the initial value, run the following command from the command line:

    aws secretsmanager create-secret \
        --name {secret_name} \
        --secret-binary fileb://{file_name}

The output will be in the form:

    {
        "ARN":
        "arn:aws:secretsmanager:<region>:<account_id>:secret:<secret_name>-<random_value>",
        "Name": "<secret_name>",
        "VersionId": "<uuidv4>"
    }

## Install the Secret rotation Lambda

Download the latest jar from
[Maven Central](https://search.maven.org/#search%7Cga%7C1%7Ca%3A%22fernet-aws-secrets-manager-rotator%22)
or from the [Releases](https://github.com/l0s/fernet-java8/releases) page.
Note that the file name pattern will be
fernet-aws-secrets-manager-rotator-{version}.jar. Then create an AWS
Lambda Function with the Java 8 runtime. Upload the jar and set the
handler to either
`com.macasaet.fernet.aws.secretsmanager.rotation.SimpleFernetKeyRotator`
or
`com.macasaet.fernet.aws.secretsmanager.rotation.MultiFernetKeyRotator`
depending on whether you will use the Simple or Multi key scheme.

If using the `MultiFernetKeyRotator`, also set the environment variable
`MAX_ACTIVE_KEYS` to control the number of active keys to retain
(including the primary key, but excluding the staged key). Be sure to
take into account the Fernet token TTL as well as the rotation frequency
when choosing this value to ensure that your application is always able
to validate and decrypt valid tokens. The default number of active keys
is 3. The value must be greater than or equal to 1.

### Permissions

#### Lambda Permissions

The Lambda Function will need permission to write logs (CloudWatch),
generate random numbers (KMS), and rotate secrets (Secrets Manager). A
sample IAM role is available
[here](https://github.com/l0s/fernet-java8/blob/master/fernet-aws-secrets-manager-rotator/src/test/resources/sample-lambda-iam-role.json).

#### Secrets Manager Permissions

In addition, Secrets Manager needs to be given permission to invoke the
new Lambda Function. This can be done using the following command:

    aws lambda add-permission \
        --function-name arn:aws:lambda:{region}:{accountId}:function:{functionName} \
        --principal secretsmanager.amazonaws.com \
        --action lambda:InvokeFunction \
        --statement-id SecretsManagerAccess

## Client Usage

Clients can use any Fernet library they choose.

The Fernet keys are stored in binary form. If using the Simple scheme,
retrieve the "AWSCURRENT" and "AWSPREVIOUS" stages of the Secret. This
will be two separate calls to Secrets Manager. If using the Multi
scheme, it is sufficient to retrieve the "AWSCURRENT" stage. The binary
payload will contain all of the keys appended to each other. Be sure to
ignore the first key (the pending key).

If using the [Java Library](https://github.com/l0s/fernet-java8), you
can use [this
constructor](https://static.javadoc.io/com.macasaet.fernet/fernet-java8/1.2.0/com/macasaet/fernet/Key.html#Key-byte:A-byte:A-)
to instantiate each key.

## Development

[PIT Mutation Testing  Report](https://l0s.github.io/fernet-java8/fernet-aws-secrets-manager-rotator/pit-reports/index.html)

## References

[AWS Secrets Manager Documentation](https://docs.aws.amazon.com/secretsmanager/latest/userguide/intro.html)

[Rotating
Secrets](https://docs.aws.amazon.com/secretsmanager/latest/userguide/rotating-secrets.html)

## License

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
