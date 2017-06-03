# fernet-java8

This is a work-in-progress implementation of the
[Fernet Spec](https://github.com/fernet/spec) using Java 8.
The goal is to use only native Java constructs to avoid pulling in any
dependencies so the library would be more generally usable.

## Open Issues

This implementation currently fails two test cases specified for [invalid tokens](https://github.com/fernet/spec/blob/f16a35d3cfd8cdb2d8c7f7d10ce6c4d6058b19d2/invalid.json):
* payload padding error
* incorrect initialisation vector.

Until these issues are resolved, the main code base will remain in `src/test`.

## Prior Art

There is a library called
[fernet-java](https://github.com/trancee/fernet-java/), which as of version
0.0.1-SNAPSHOT, uses Guava and commons-codec.
