# Fernet Java

[![Build Status](https://github.com/l0s/fernet-java8/actions/workflows/ci.yml/badge.svg?branch=master)](https://github.com/l0s/fernet-java8/actions/workflows/ci.yml)
[![Javadocs](https://javadoc.io/badge/com.macasaet.fernet/fernet-java8.svg)](https://javadoc.io/doc/com.macasaet.fernet/fernet-java8)
[![Known Vulnerabilities](https://snyk.io/test/github/l0s/fernet-java8/badge.svg?targetFile=pom.xml)](https://snyk.io/test/github/l0s/fernet-java8?targetFile=pom.xml)
[![OpenSSF Best Practices](https://bestpractices.coreinfrastructure.org/projects/6199/badge)](https://bestpractices.coreinfrastructure.org/projects/6199)

This is an implementation of the
[Fernet Spec](https://github.com/fernet/spec) using Java.
The goal is to use only native Java constructs to avoid pulling in any
dependencies so the library would be more generally usable. It also takes
advantage of the Java time objects to add type-safety.

I am actively soliciting feedback on this library. If you have any thoughts,
please [submit an issue](https://github.com/l0s/fernet-java8/issues).

## Features
* fully-validated against the scenarios in the [Fernet Spec](https://github.com/fernet/spec)
* type-safety by using Java time objects (no confusing milliseconds vs seconds after the epoch)
* no dependencies!
* pluggable mechanism so you can specify your own:
    * Clock
    * TTL / max clock skew
    * payload validator
    * payload transformation (i.e. to POJO)

## Adding this to your project

This library is available in
[The Central Repository](https://repo1.maven.org/maven2/com/macasaet/fernet/fernet-java8/).
If you use Maven, you can add it to your project object model using:

    <dependency>
      <groupId>com.macasaet.fernet</groupId>
      <artifactId>fernet-java8</artifactId>
      <version>1.4.2</version>
    </dependency>

For more details, see: 
[The Central Repository](https://search.maven.org/#search%7Cga%7C1%7Cg%3A%22com.macasaet.fernet%22%20AND%20a%3A%22fernet-java8%22)

If you use a dependency manager system or build system other than Maven, see
[Dependency Information](https://l0s.github.io/fernet-java8/fernet-java8/dependency-info.html).

Alternatively, you can just download the latest
[jar](https://github.com/l0s/fernet-java8/releases) and add it to your
classpath. It does not have any dependencies.

Note that this library requires Java 8 or higher.

## Examples

Create a new key:

    final Key key = Key.generateKey();

or

    final Key key = Key.generateKey(customRandom);

Deserialise an existing key:

    final Key key = new Key("cw_0x689RpI-jtRR7oE8h_eQsKImvJapLeSbXpwF4e4=");

Create a token:

    final Token token = Token.generate(key, "secret message");

or

    final Token token = Token.generate(customRandom, key, "secret message");

Deserialise an existing token:

    final Token token = Token.fromString("gAAAAAAdwJ6wAAECAwQFBgcICQoLDA0ODy021cpGVWKZ_eEwCGM4BLLF_5CV9dOPmrhuVUPgJobwOz7JcbmrR64jVmpU4IwqDA==");

Validate the token:

    final Validator<String> validator = new StringValidator() {
    };
    final String payload = token.validateAndDecrypt(key, validator);

When validating, an exception is thrown if the token is not valid.  In this
example, the payload is just the decrypted cipher text portion of the token.
If you choose to store structured data in the token (e.g. JSON), or a
pointer to a domain object (e.g. a username), you can implement your own
`Validator<T>` that returns the type of POJO your application expects.

Use a custom time-to-live:

    final Validator<String> validator = new StringValidator() {
      public TemporalAmount getTimeToLive() {
        return Duration.ofHours(4);
      }
    };

The default time-to-live is 60 seconds, but in this example, it's
overridden to 4 hours.

### Storing Sensitive Data on the Client

For an example of how to securely store sensitive data on the client (e.g. browser cookie), see the classes in
[src/test/java](https://github.com/l0s/fernet-java8/tree/master/fernet-java8/src/test/java/com/macasaet/fernet/example/autofill). The class 
[AutofillExample](https://github.com/l0s/fernet-java8/blob/master/fernet-java8/src/test/java/com/macasaet/fernet/example/autofill/AutofillExampleIT.java) 
shows a full end-to-end example.

### JAX-RS / JSR 311

For details on how to use Fernet tokens to secure JAX-RS endpoints, see
the
[fernet-jersey-auth](https://github.com/l0s/fernet-java8/tree/master/fernet-jersey-auth)
submodule. If you're using the Jersey implementation of JAX-RS, you can
use that module directly.
[TokenInjectionIT](https://github.com/l0s/fernet-java8/blob/master/fernet-jersey-auth/src/test/java/com/macasaet/fernet/jersey/example/tokeninjection/TokenInjectionIT.java)
contains an example of injecting a Fernet token into an endpoint
parameter.
[SecretInjectionIT](https://github.com/l0s/fernet-java8/blob/master/fernet-jersey-auth/src/test/java/com/macasaet/fernet/jersey/example/secretinjection/SecretInjectionIT.java)
contains an example of injecting a Fernet token payload into an
endpoint parameter.

### AWS Secrets Manager

For details on how to store Fernet keys using AWS Secrets Manager, see
the submodule
[fernet-aws-secrets-manager-rotator](https://github.com/l0s/fernet-java8/tree/master/fernet-aws-secrets-manager-rotator).
It includes a Lambda Function to enable key rotation.

## Development

See [CONTRIBUTING.md](CONTRIBUTING.md) for details on how to build this
project.

## Prior Art

There is a library called
[fernet-java](https://github.com/trancee/fernet-java/), which as of version
0.0.1-SNAPSHOT, uses Guava and commons-codec.

## License

   Copyright 2017 Carlos Macasaet

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

   https://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
