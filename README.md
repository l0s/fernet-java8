# fernet-java8

[![Build Status](https://travis-ci.org/l0s/fernet-java8.svg?branch=master)](https://travis-ci.org/l0s/fernet-java8)

This is a work-in-progress implementation of the
[Fernet Spec](https://github.com/fernet/spec) using Java 8.
The goal is to use only native Java constructs to avoid pulling in any
dependencies so the library would be more generally usable.

## Open Issues

All test cases pass now, and I am working on the API design. Until that is
fleshed out, the main code base will remain in `src/test`. Also, expect the
API to remain in flux until major version 1 (1.0.0).

## Prior Art

There is a library called
[fernet-java](https://github.com/trancee/fernet-java/), which as of version
0.0.1-SNAPSHOT, uses Guava and commons-codec.
