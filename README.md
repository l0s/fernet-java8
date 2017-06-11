# fernet-java8

[![Build Status](https://travis-ci.org/l0s/fernet-java8.svg?branch=master)](https://travis-ci.org/l0s/fernet-java8)

This is a work-in-progress implementation of the
[Fernet Spec](https://github.com/fernet/spec) using Java 8.
The goal is to use only native Java constructs to avoid pulling in any
dependencies so the library would be more generally usable. It also takes
advantage of the Java 8 time objects to add type-safety.

## Features
* fully-validated against the scenarios in the [Fernet Spec](https://github.com/fernet/spec)
* type-safety by using Java 8 time objects (no confusing milliseconds vs seconds after the epoch)
* no dependencies!
* pluggable mechanism so you can specify your own:
** Clock
** TTL / max clock skew
** payload validator
** payload transformation (i.e. to POJO)

## Examples

Create a new key:

    final Key key = Key.generateKey(random);

Create a token:

    final Token token = Token.generate(random, key, "secret message");

Validate the token:

    final Validator<String> validator = new StringValidator() {
    };
    final String payload = token.validateAndDecrypt(key, validator);

Or:

    final Instant now = Instant.now();
    final String payload = token.validateAndDecrypt(key, now.minus(Duration.ofSeconds(60)), now.plus(Duration.ofSeconds(60)));

### JAX-RS / Jersey

For an example of how to use Fernet Tokens to secure a REST API implemented
using  JAX-RS / Jersey, see the classes in
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

## Notes

### Mutation Testing and Test Coverage

`mvn clean install org.pitest:pitest-maven:mutationCoverage site`

## Prior Art

There is a library called
[fernet-java](https://github.com/trancee/fernet-java/), which as of version
0.0.1-SNAPSHOT, uses Guava and commons-codec.
