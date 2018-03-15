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

This is just a wrapper on the JwtTool, which you can read about below. It specifies the Java command line and classpath, and it defaults some of the options for this example.

```
createJwt.sh  -k ./private-20170130-105203.pem -i kjskjsksj  -e test -o amer-demo4
```

## JwtTool

This tool allows you to decode a JWT, verify an RSA-signed JWT, or generate an RSA-signed JWT.

## Create a signed JWT
```
 java -classpath "jwttool/target/jwt-tool.jar:jwttool/target/lib/*"  com.google.examples.JwtTool \
   -g \
   -i keyid1 \
   -x 365d \
   -k ./private-20170130-105203.pem \
   -c '{
       "sub"   : "DinoChiesa-01918712-C042-49AC-803C-C8CA635D4E64",
       "iss"   : "urn://apigee-edge-jwt-issuer-20170809",
       "scope" : "urn://www.apigee.com/apis/forever",
       "aud"   : "urn://www.apigee.com/the-google-kirkland-office"
   }'
```

The above says:
* create a JWT (-g)
* using keyid keyid1 (-i)
* with expiration of 365 days
* using the specified private key
* and the specified claims


## Verify a signed JWT

This will not verify the JWT:

```
 java -classpath "jwttool/target/jwt-tool.jar:jwttool/target/lib/*"  com.google.examples.JwtTool \
   -p \
   -t $JWT \
   -k ./public-20170130-105203.pem

```
The above says:
* parse a JWT (-p)
* given the provided token (-t)
* with the provided public key (-k)


## Decode a signed JWT

This will not verify the JWT:

```
 java -classpath "jwttool/target/jwt-tool.jar:jwttool/target/lib/*"  com.google.examples.JwtTool \
   -p \
   -t $JWT
```
