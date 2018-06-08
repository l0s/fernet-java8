# Fernet Java

[![Build Status](https://travis-ci.org/l0s/fernet-java8.svg?branch=master)](https://travis-ci.org/l0s/fernet-java8)
[![Javadocs](https://javadoc.io/badge/com.macasaet.fernet/fernet-java8.svg)](https://javadoc.io/doc/com.macasaet.fernet/fernet-java8)
[![Known Vulnerabilities](https://snyk.io/test/github/l0s/fernet-java8/badge.svg?targetFile=pom.xml)](https://snyk.io/test/github/l0s/fernet-java8?targetFile=pom.xml)
[![Sonar](https://sonarcloud.io/api/project_badges/measure?project=com.macasaet.fernet%3Afernet-java8&metric=alert_status)](https://sonarcloud.io/dashboard?id=com.macasaet.fernet%3Afernet-java8)

This is an implementation of the
[Fernet Spec](https://github.com/fernet/spec) using Java 8.
The goal is to use only native Java constructs to avoid pulling in any
dependencies so the library would be more generally usable. It also takes
advantage of the Java 8 time objects to add type-safety.

I am actively soliciting feedback on this library. If you have any thoughts,
please [submit an issue](https://github.com/l0s/fernet-java8/issues).

## Features
* fully-validated against the scenarios in the [Fernet Spec](https://github.com/fernet/spec)
* type-safety by using Java 8 time objects (no confusing milliseconds vs seconds after the epoch)
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
      <version>1.1.3</version>
    </dependency>

For more details, see: 
[The Central Repository](https://search.maven.org/#artifactdetails%7Ccom.macasaet.fernet%7Cfernet-java8%7C1.0.0%7Cjar)

If you use a dependency manager system or build system other than Maven, see
[Dependency Information](https://l0s.github.io/fernet-java8/dependency-info.html).

Alternatively, you can just download the latest
[jar](https://github.com/l0s/fernet-java8/releases) and add it to your
classpath. It does not have any dependencies.

Note that this library requires Java 8 or higher.

## Examples

Create a new key:

    final Key key = Key.generateKey(random);

Deserialise an existing key:

    final Key key = new Key("cw_0x689RpI-jtRR7oE8h_eQsKImvJapLeSbXpwF4e4=");

Create a token:

    final Token token = Token.generate(random, key, "secret message");

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

### Storing Sensitive Data on the Client

For an example of how to securely store sensitive data on the client (e.g. browser cookie), see the classes in
[src/test/java](https://github.com/l0s/fernet-java8/tree/master/src/test/java/com/macasaet/fernet/example/autofill). The class 
[AutofillExample](https://github.com/l0s/fernet-java8/blob/master/src/test/java/com/macasaet/fernet/example/autofill/AutofillExample.java) 
shows a full end-to-end example.

### JAX-RS

For an example of how to use Fernet Tokens to secure a REST API implemented
using  JAX-RS or Jersey, see the classes in
[src/test/java](https://github.com/l0s/fernet-java8/tree/master/src/test/java/com/macasaet/fernet/example/jaxrs).
The test class
[JaxRsTest](https://github.com/l0s/fernet-java8/blob/master/src/test/java/com/macasaet/fernet/example/jaxrs/JaxRsTest.java)
shows a full end-to-end example. It includes an example of integrating with
external storage.

## Why Fernet, Why not JWT?

Valid concerns have been raised about the JWT specification:
* [No Way, JOSE! Javascript Object Signing and Encryption is a Bad Standard That Everyone Should Avoid](https://paragonie.com/blog/2017/03/jwt-json-web-tokens-is-bad-standard-that-everyone-should-avoid)
* [JSON Web Tokens should be avoided](https://news.ycombinator.com/item?id=13865459)

In addition, Fernet has been available in Python's
[cryptography](https://github.com/pyca/cryptography) package for some time.
It is also used by
[Keystone, the OpenStack identity service](https://docs.openstack.org/keystone/latest/admin/identity-fernet-token-faq.html).

## Development

### Mutation Testing and Test Coverage

This project uses PITest to evaluate test coverage and test effectiveness.
The latest report is available [here](https://l0s.github.io/fernet-java8/fernet-java8/pit-reports/).
To generate a report for a local build, run:

    mvn clean install site

### Releasing to The Central Repository

    mvn --batch-mode -Prelease clean release:clean release:prepare release:perform

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
