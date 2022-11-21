# Contributing

Thank you for your interest in participating in this project! 

## Development Guidelines

### Automated Testing

When adding a new feature, please ensure it includes automated tests.
When fixing bugs, please ensure at least one automated test reproduces
the bug.

For unit testing, the project must have at least 75% code coverage at
all times and 75% mutation coverage at all times. These thresholds are
programmatically enforced. If you feel they need to be relaxed, please
explain your reasoning in the pull request.

This project uses PITest to evaluate test coverage and test effectiveness.
The latest report is available
[here](https://l0s.github.io/fernet-java8/fernet-java8/pit-reports/index.html).
To generate a report for a local build, run:

    ./mvnw clean install site

### Static Analysis

This project uses
[PMD](https://l0s.github.io/fernet-java8/fernet-java8/pmd.html)
and [CodeQL](https://github.com/l0s/fernet-java8/security/code-scanning) for
static analysis. Please do not circumvent these tools. If you feel a rule
needs to be disabled or configured differently, please explain your
reasoning in the pull request.

## Development

To build the project locally, run:

    ./mvnw clean install

To build using different JDK versions, use [jEnv](https://www.jenv.be/).

### Releasing to The Central Repository

This can only be done by the maintainer as it requires the appropriate
Sonatype credentials and the PGP signing key.

    ./mvnw --batch-mode -Prelease clean release:clean release:prepare release:perform

## License

   Copyright 2022 Carlos Macasaet

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

   https://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and 
   limitations under the License.
