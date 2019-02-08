# Tools to assist

Contained here are some tools to assist with the RFC7523 Apigee example.

## provisionKeysProxyProductDeveloperAndApp.sh

This tool provisions the various things for the example.

It creates keys, imports and deploys a proxy, creates an API Product, a Developer and a
Developer app for the API Product.  It prints out the client id and secret.

```
./provisionKeysProxyProductDeveloperAndApp.sh -n -o amer-demo4 -e test
```

## createJwt.sh

This is just a wrapper on the JwtTool, which you can read about below. It
specifies the Java command line and classpath, and it defaults some of the
options for this example.

```
ORG=myorgname
createJwt.sh  -k ./private-20170130-105203.pem -i kjskjsksj  -e test -o $ORG
```

## JwtTool

This tool allows you to decode a JWT, verify an RSA-signed JWT, or generate an RSA-signed JWT.

## Create a signed JWT
```
 java -classpath "jose-tool/target/apigee-jose-tool-20190207.jar:jose-tool/target/lib/*"  com.google.examples.JwtTool \
   -G -A RS256 \
   -i keyid1 \
   -x 18h \
   -k ./private-20170130-105203.pem \
   -c '{
       "sub"   : "DinoChiesa-01918712-C042-49AC-803C-C8CA635D4E64",
       "iss"   : "urn://apigee-edge-jwt-issuer-20170809",
       "scope" : "urn://www.apigee.com/apis/forever",
       "aud"   : "urn://www.apigee.com/the-google-kirkland-office"
   }'
```

The above says:
* create a JWT (-G) using the RS256 algorithm (-A RS256)
* using keyid keyid1 (-i)
* with expiration of 18 hours
* using the specified private key
* and the specified claims


## Verify a signed JWT

This will verify the JWT:

```
 java -classpath "jose-tool/target/apigee-jose-tool-20190207.jar:jose-tool/target/lib/*"  com.google.examples.JwtTool \
   -V \
   -t $JWT \
   -k ./public-20170130-105203.pem
```

The above says:
* verify a JWT (-V)
* given the provided token (-t)
* with the provided public key (-k)


## Decode a signed JWT, without verifying the signature

This will parse, but will not verify the JWT:

```
 java -classpath "jwttool/target/jwt-tool.jar:jwttool/target/lib/*"  com.google.examples.JwtTool \
   -V \
   -t $JWT
```
