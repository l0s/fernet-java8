# fernet-java8

[![Build Status](https://travis-ci.org/l0s/fernet-java8.svg?branch=master)](https://travis-ci.org/l0s/fernet-java8)
[![Javadocs](https://javadoc.io/badge/com.macasaet.fernet/fernet-java8.svg)](https://javadoc.io/doc/com.macasaet.fernet/fernet-java8)

This is a work-in-progress implementation of the
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
      <version>0.2.2</version>
    </dependency>

If you use a dependency manager system or build system other than Maven,see
[The Central Repository](https://search.maven.org/#artifactdetails%7Ccom.macasaet.fernet%7Cfernet-java8%7C0.2.2%7Cjar)
page for details on how to integrate it.

Alternatively, you can just download the latest
[jar](https://github.com/l0s/fernet-java8/releases) and add it to your
classpath. It does not have any dependencies.

Note that this library requires Java 8 or higher.

## Examples

Create a new key:

    final Key key = Key.generateKey(random);

Deserialise an existing key:

    final Key key = Key.fromString("cw_0x689RpI-jtRR7oE8h_eQsKImvJapLeSbXpwF4e4=");

Create a token:

    final Token token = Token.generate(random, key, "secret message");

Deserialise an existing token:

    final Token token = Token.fromString("gAAAAAAdwJ6wAAECAwQFBgcICQoLDA0ODy021cpGVWKZ_eEwCGM4BLLF_5CV9dOPmrhuVUPgJobwOz7JcbmrR64jVmpU4IwqDA==");

Validate the token:

    final Validator<String> validator = new StringValidator() {
    };
    final String payload = token.validateAndDecrypt(key, validator);

Or:

    final Instant now = Instant.now();
    final String payload = token.validateAndDecrypt(key, now.minus(Duration.ofSeconds(60)), now.plus(Duration.ofSeconds(60)));

When validating, an exception is thrown if the token is not valid.  In this
example, the payload is just the decrypted cipher text portion of the token.
If you choose to store structured data in the token (e.g. JSON), or a
pointer to a domain object (e.g. a username), you can implement your own
`Validator<T>` that returs the type of POJO your application expects.

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
* https://paragonie.com/blog/2017/03/jwt-json-web-tokens-is-bad-standard-that-everyone-should-avoid
* https://news.ycombinator.com/item?id=13865459

In addition, Fernet has been available in Python's
[cryptography](https://github.com/pyca/cryptography) package for some time.

## Open Issues

All test cases pass now, and I am working on the API design. Expect the
API to remain in flux until major version 1 (1.0.0).

## Development

### Mutation Testing and Test Coverage

This project uses PITest to evaluate test coverage and test effectiveness.
To see a report, run:

    mvn clean install site

### Releasing to The Central Repository

    mvn --batch-mode -Prelease clean release:clean release:prepare release:perform

## Prior Art

There is a library called
[fernet-java](https://github.com/trancee/fernet-java/), which as of version
0.0.1-SNAPSHOT, uses Guava and commons-codec.
