#!/bin/sh

set -e
set -u
set -x

# Build the project to fuzz and extract the version
mvn -Dmaven.test.skip=true \
  -DskipTests \
  --projects fernet-java8 \
  --also-make \
  install
artifact_version=$(mvn --file fernet-java8/pom.xml \
  org.apache.maven.plugins:maven-help-plugin:3.2.0:evaluate \
  -Dexpression=project.version -q -DforceStdout)
cp "fernet-java8/target/fernet-java8-${artifact_version}.jar" \
  "${OUT}/fernet-java8.jar"

# Build the fuzzers

mvn --file fernet-fuzzer/pom.xml \
  -Dfernet.version="$artifact_version" \
  -DskipTests \
  package
cp fernet-fuzzer/target/fernet-fuzzer-*.jar "${OUT}/fernet-fuzzer.jar"

RUNTIME_CLASSPATH="${OUT}/fernet-java8.jar:${OUT}/fernet-fuzzer.jar"

# if there are more fuzzers, turn this into a loop

cp /src/default.options "${OUT}/TokenEncryptDecryptFuzzer.options"

cat << EOF > "${OUT}/TokenEncryptDecryptFuzzer"
#!/bin/sh
this_dir=\$(dirname "\$0")
export LD_LIBRARY_PATH=${JVM_LD_LIBRARY_PATH}
export ASAN_OPTIONS="\${ASAN_OPTIONS}:symbolize=1:external_symbolizer_path=\${this_dir}/llvm-symbolizer:detect_leaks=0"
"\${this_dir}/jazzer_driver" \
  --agent_path="\${this_dir}/jazzer_agent_deploy.jar" \
  --cp="$RUNTIME_CLASSPATH" \
  --target_class=TokenEncryptDecryptFuzzer \
  --jvm_args="-Xmx2048m:-Djava.awt.headless=true" \
  $@
EOF
chmod +x "${OUT}/TokenEncryptDecryptFuzzer"
