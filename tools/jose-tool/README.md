# JOSE Tool

This repo includes 2 distinct tools - one for creating signed
JWT and verifying same, and another for creating signed JWS
and verifying same. They both depend on the Nimbusds JOSE
library.

The underlying nimbusds JOSE library and this tool support all combinations of the following algorithms:
{HS,ES,RS,PS}{256,384,512}

# Usage Examples

## Generate JWS signed with RS256

```
tooldir=/Users/dchiesa/dev/java/nimbusds-jose-tool/target
version=20190207
java -classpath "$tooldir/nimbusds-jose-tool-$version.jar:$tooldir/lib/*" \
  com.google.examples.JwsTool \
  -G \
  -A RS256 \
  -k testkeys/rsa-private-unencrypted-201810209.pem \
  -H '{"hdr1":123, "cty": "text/plain", "typ": "JOSE"}' \
  -p payloadhere \
  -v
```

## Generate JWS signed with RS256, with Detached content

```
java -classpath "$tooldir/nimbusds-jose-tool-$version.jar:$tooldir/lib/*"   \
   com.google.examples.JwsTool \
   -G -A RS256 \
   -k testkeys/rsa-private-unencrypted-201810209.pem \
   -H '{"hdr1":123, "cty": "text/plain", "typ": "JOSE"}' \
   -f file-containing-content-to-be-detached \
   -v \
   -D
```

## Verify a JWS

```
tooldir=/Users/dchiesa/dev/java/nimbusds-jose-tool/target
version=20190207
java -classpath "$tooldir/nimbusds-jose-tool-$version.jar:$tooldir/lib/*" \
  com.google.examples.JwsTool \
  -V \
  -k testkeys/rsa-public-201810209.pem \
  -b $JWS
  -v
```

## Verify JWS with detached content

```
tooldir=/Users/dchiesa/dev/java/nimbusds-jose-tool/target

java -classpath "$tooldir/nimbusds-jose-tool-$version.jar:$tooldir/lib/*" \
  com.google.examples.JwsTool \
  -V \
  -f file-containing-detached-content \
  -k testkeys/rsa-public-201810209.pem \
  -b $JWS \
  -v
```

## Generate JWT signed with RS256

```
tooldir=/Users/dchiesa/dev/java/nimbusds-jose-tool/target
version=20190207
java -classpath "$tooldir/nimbusds-jose-tool-$version.jar:$tooldir/lib/*" \
  com.google.examples.JwtTool \
  -G \
  -A RS256 \
  -k testkeys/rsa-private-unencrypted-201810209.pem \
  -H '{"hdr1":123, "hdr2": true, "crit" : ["hdr1", "hdr2"]}' \
  -c '{"sub" : "dino@example.org"}' \
  -v
```

## Generate JWT signed with PS256

This uses the same RSA private key.

```
tooldir=/Users/dchiesa/dev/java/nimbusds-jose-tool/target
version=20190207
java -classpath "$tooldir/nimbusds-jose-tool-$version.jar:$tooldir/lib/*" \
  com.google.examples.JwtTool \
  -G \
  -A PS256 \
  -k testkeys/rsa-private-unencrypted-201810209.pem \
  -H '{"hdr1":123, "hdr2": true, "crit" : ["hdr1", "hdr2"]}' \
  -c '{"sub" : "dino@example.org"}' \
  -v
```


## Generate JWT signed with ES256

This uses an ECDSA key.

```
tooldir=/Users/dchiesa/dev/java/nimbusds-jose-tool/target
version=20190207
java -classpath "$tooldir/nimbusds-jose-tool-$version.jar:$tooldir/lib/*" \
  com.google.examples.JwtTool \
  -G \
  -A ES256 \
  -k testkeys/ec-private-prime256v1-unencrypted.pem \
  -H '{"hdr1":123, "hdr2": true, "crit" : ["hdr1", "hdr2"]}' \
  -c '{"sub" : "dino@example.org"}' \
  -v
```

## Verify a JWT signed with ES256

```
java -classpath "$tooldir/nimbusds-jose-tool-$version.jar:$tooldir/lib/*" \
  com.google.examples.JwtTool \
  -V \
  -t $JWT \
  -k testkeys/ec-public-prime256v1.pem \
  -v
```

## Generate JWT signed with HS256

This uses a secret key, specified on the command line.

```
tooldir=/Users/dchiesa/dev/java/nimbusds-jose-tool/target
version=20190207
java -classpath "$tooldir/nimbusds-jose-tool-$version.jar:$tooldir/lib/*" \
  com.google.examples.JwtTool \
  -G \
  -A HS256 \
  -s ABCDEFGHIJKLMNOPQRSTUV1234567890 \
  -H '{"hdr1":123, "hdr2": true, "crit" : ["hdr1", "hdr2"]}' \
  -c '{"sub" : "dino@example.org"}' \
  -v
```

## Generate JWT signed with ES384

This uses an _encrypted_ ECDSA key.

```
tooldir=/Users/dchiesa/dev/java/nimbusds-jose-tool/target
version=20190207
java -classpath "$tooldir/nimbusds-jose-tool-$version.jar:$tooldir/lib/*" \
  com.google.examples.JwtTool \
  -G \
  -A ES384 \
  -k testkeys/ec-private-secp384r1-encrypted-des3.pem \
  -P Quickly \
  -H '{"hdr1":123, "hdr2": true, "crit" : ["hdr1", "hdr2"]}' \
  -c '{"sub" : "dino@example.org"}' \
  -v
```
