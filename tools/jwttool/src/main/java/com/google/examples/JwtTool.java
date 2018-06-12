// JwtTool.java
// ------------------------------------------------------------------
//
// This tool uses the Nimbus library to parse or generate a JWT.
//
// Copyright 2016-2018 Google LLC.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

package com.google.examples;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jwt.ReadOnlyJWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Hashtable;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import net.minidev.json.JSONObject;
import net.minidev.json.JSONStyleIdent;
import net.minidev.json.JSONValue;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang.time.DurationFormatUtils;
import org.apache.commons.ssl.PKCS8Key;

public class JwtTool {
    private final String optString = "pgvt:c:k:x:i:I:A:"; // getopt style
    private JwtAction jwtAction = JwtAction.NONE;
    private JWSAlgorithm jwsAlg = JWSAlgorithm.RS256;
    private final static JOSEObjectType TYP_JWT = new JOSEObjectType("JWT");

    public JwtTool (String[] args) throws java.lang.Exception {
        GetOpts(args, optString);
    }

    enum JwtAction { NONE, PARSE, GENERATE };

    private Hashtable<String, Object> options = new Hashtable<String, Object> ();

    public static class TimeResolver {
        private final static Pattern expiryPattern =
            Pattern.compile("^([1-9][0-9]*)(ms|s|m|h|d|w|)$", Pattern.CASE_INSENSITIVE);
        private final static Map<String,Long> timeMultipliers;
        static {
            Map<String,Long> m1 = new HashMap<String,Long>();
            m1.put("s", 1L);
            m1.put("m", 60L);
            m1.put("h", 60L*60);
            m1.put("d", 60L*60*24);
            m1.put("w", 60L*60*24*7);
            //m1.put("y", 60*60*24*365*1000);
            timeMultipliers = m1;
        }
        private final static String defaultUnit = "s";
        public static Date getExpiryDate(String expiresInString) {
            Calendar cal = Calendar.getInstance();
            Long milliseconds = resolveExpression(expiresInString);
            Long seconds = milliseconds/1000;
            int secondsToAdd = seconds.intValue();
            if (secondsToAdd<= 0) return null; /* no expiry */
            cal.add(Calendar.SECOND, secondsToAdd);
            Date then = cal.getTime();
            return then;
        }

        /*
         * convert a simple timespan string, expressed in days, hours, minutes, or
         * seconds, such as 30d, 12d, 8h, 24h, 45m, 30s, into a numeric quantity in
         * seconds. Default TimeUnit is ms. Eg. 30 is treated as 30ms.
         */
        public static Long resolveExpression(String subject) {
            Matcher m = expiryPattern.matcher(subject);
            if (m.find()) {
                String key = m.group(2);
                if(key.equals(""))
                    key = defaultUnit;
                return Long.parseLong(m.group(1),10) * timeMultipliers.get(key);
            }
            return -1L;
        }
    }

    private void GetOpts(String[] args, String optString)
        throws java.lang.Exception {
        // Parse command line args for args in the following format:
        //   -a value -b value2 ... ...

        // sanity checks
        if (args == null) return;
        if (args.length == 0) return;
        if (optString == null) return;
        final String argPrefix = "-";
        String patternString = "^" + argPrefix + "([" + optString.replaceAll(":","") + "])";

        java.util.regex.Pattern p = java.util.regex.Pattern.compile(patternString);

        int L = args.length;
        for(int i=0; i < L; i++) {
            String arg = args[i];
            java.util.regex.Matcher m = p.matcher(arg);
            if (!m.matches()) {
                throw new java.lang.Exception(String.format("unknown or malformed option %s.", arg));
            }

            char ch = arg.charAt(1);
            int pos = optString.indexOf(ch);

            if ((pos != optString.length() - 1) && (optString.charAt(pos+1) == ':')) {
                if (i+1 < L) {
                    i++;
                    Object current = this.options.get(m.group(1));
                    ArrayList<String> newList;
                    if (current == null) {
                        // not a previously-seen option
                        this.options.put(m.group(1), args[i]);
                    }
                    else if (current instanceof ArrayList<?>) {
                        // previously seen, and already a lsit
                        newList = (ArrayList<String>) current;
                        newList.add(args[i]);
                    }
                    else {
                        // we have one value, need to make a list
                        newList = new ArrayList<String>();
                        newList.add((String)current);
                        newList.add(args[i]);
                        this.options.put(m.group(1), newList);
                    }
                }
                else {
                    throw new java.lang.Exception("Incorrect arguments.");
                }
            }
            else {
                // a "no-value" argument, like -v for verbose
                options.put(m.group(1), (Boolean) true);
            }
        }
    }

    private static ArrayList<String> asOptionsList(Object o) {
        if (o instanceof ArrayList<?>) {
            return (ArrayList<String>) o;
        }

        ArrayList<String> list = new ArrayList<String>();

        if (o instanceof String) {
            list.add((String)o);

        }
        return list;
    }

    private void maybeShowOptions() {
        Boolean verbose = (Boolean) this.options.get("v");
        if (verbose != null && verbose) {
            System.out.println("options:");
            Enumeration e = this.options.keys();
            while(e.hasMoreElements()) {
                // iterate through Hashtable keys Enumeration
                String k = (String) e.nextElement();
                Object o = this.options.get(k);
                String v = null;
                v = (o.getClass().equals(Boolean.class)) ?  "true" : (String) o;
                System.out.println("  " + k + ": " + v);
            }
        }
    }

    private void determineAction() {
        Boolean parse = (Boolean) this.options.get("p");
        Boolean generate = (Boolean) this.options.get("g");
        if (parse != null && parse && generate==null) {
            jwtAction = JwtAction.PARSE;
        }
        else if (generate != null && generate && parse == null) {
            jwtAction = JwtAction.GENERATE;
        }
    }


    private Date getExpiryDate() {
        Date current = new Date();
        Calendar cal = Calendar.getInstance();
        cal.setTime(current);

        int lifetimeInSeconds = 300;
        String expiry = (String) this.options.get("x");
        if (expiry != null) {
            lifetimeInSeconds = TimeResolver.resolveExpression(expiry).intValue();
        }
        cal.add(Calendar.SECOND, lifetimeInSeconds);
        Date then = cal.getTime();
        return then;
    }

    private RSAPrivateKey getPrivateKey(byte[] keyBytes)
        throws InvalidKeySpecException, GeneralSecurityException, NoSuchAlgorithmException
    {
        // If the provided data is encrypted, we need a password to decrypt
        // it. If the InputStream is not encrypted, then the password is ignored
        // (can be null).  The InputStream can be DER (raw ASN.1) or PEM (base64).
        // char[] password = (info.password != null && !info.password.isEmpty()) ?
        //     info.password.toCharArray() : null;
        char[] password = null;

        PKCS8Key pkcs8 = new PKCS8Key( keyBytes, password );

        // If an unencrypted PKCS8 key was provided, then getDecryptedBytes()
        // actually returns exactly what was originally passed in (with no
        // changes). If an OpenSSL key was provided, it gets reformatted as
        // PKCS #8.
        byte[] decrypted = pkcs8.getDecryptedBytes();
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec( decrypted );

        // A Java PrivateKey object is born.
        PrivateKey pk = null;
        if ( pkcs8.isDSA() ) {
            pk = KeyFactory.getInstance( "DSA" ).generatePrivate( spec );
        }
        else if ( pkcs8.isRSA() ) {
            pk = KeyFactory.getInstance( "RSA" ).generatePrivate( spec );
        }
        return (RSAPrivateKey) pk;
    }

    private byte[] getPrivateKeyBytes(String filename) throws IOException {
        InputStream in = new FileInputStream(filename);
        byte[] keyBytes = new byte[in.available()];
        in.read(keyBytes);
        in.close();

        String privateKeyString = new String(keyBytes, StandardCharsets.UTF_8);
        privateKeyString = privateKeyString.trim();

        if (privateKeyString.startsWith("-----BEGIN PRIVATE KEY-----") &&
            privateKeyString.endsWith("-----END PRIVATE KEY-----")) {
            privateKeyString = privateKeyString.substring(27, privateKeyString.length() - 25);
        }
        else if (privateKeyString.startsWith("-----BEGIN RSA PRIVATE KEY-----") &&
                 privateKeyString.endsWith("-----END RSA PRIVATE KEY-----")) {
            privateKeyString = privateKeyString.substring(31, privateKeyString.length() - 29);
        }

        // clear any leading whitespace on each line
        privateKeyString = privateKeyString.replaceAll("([\\r|\\n] +)","\n");
        keyBytes = Base64.decodeBase64(privateKeyString);

        return keyBytes;
    }

    private byte[] getPublicKeyBytes(String filename) throws IOException {
        InputStream in = new FileInputStream(filename);
        byte[] keyBytes = new byte[in.available()];
        in.read(keyBytes);
        in.close();

        String s = new String(keyBytes, StandardCharsets.UTF_8);
        s = s.trim();

        if (s.startsWith("-----BEGIN RSA PUBLIC KEY-----") &&
            s.endsWith("-----END RSA PUBLIC KEY-----")) {
            s = s.substring(30, s.length() - 28);
            s = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A" + s;
        }
        else if (s.startsWith("-----BEGIN PUBLIC KEY-----") &&
                 s.endsWith("-----END PUBLIC KEY-----")) {
            s = s.substring(26, s.length() - 24);
        }

        s = s.replaceAll("[\\r|\\n| ]","");
        keyBytes = Base64.decodeBase64(s);
        return keyBytes;
    }

    private PublicKey getPublicKey(byte[] keyBytes)
        throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PublicKey key = keyFactory.generatePublic(spec);
        return key;
    }


    public void run() throws Exception {
        JSONObject json;
        maybeShowOptions();
        determineAction();
        String alg = (String) this.options.get("A");
        if (alg!= null) {
            jwsAlg = new JWSAlgorithm(alg);
        }
        if (jwtAction == JwtAction.PARSE) {
            String token = (String) this.options.get("t");

            SignedJWT signedJwt = SignedJWT.parse(token);
            JWSHeader header = signedJwt.getHeader();
            json = header.toJSONObject();
            String prettyJson = json.toString(new JSONStyleIdent());
            System.out.println("header: " + prettyJson.replaceAll("\\\\/", "/"));

            ReadOnlyJWTClaimsSet claims = signedJwt.getJWTClaimsSet();
            json = claims.toJSONObject();

            //System.out.println("payload: " + json.toString());
            prettyJson = json.toString(new JSONStyleIdent());
            System.out.println("payload: " + prettyJson.replaceAll("\\\\/", "/"));

            String publicKeyFile = (String) this.options.get("k");
            if (publicKeyFile != null) {
                RSAPublicKey publicKey = (RSAPublicKey) getPublicKey(getPublicKeyBytes(publicKeyFile));
                JWSVerifier verifier = new RSASSAVerifier(publicKey);
                if (!signedJwt.verify(verifier)) {
                    System.out.printf("Warning: The signature cannot be verified.\n");
                }
                else {
                    System.out.printf("The signature was verified.\n");
                }
                if (header.getAlgorithm() != jwsAlg) {
                    System.out.printf("Algorithm mismatch. (expected %s , actual %s)\n", jwsAlg.toString(), header.getAlgorithm().toString());
                }
            }
            else {
                System.out.printf("Warning: No public key, not able to verify the signature.\n");
            }
            Date now = new Date();
            Date t1 = claims.getIssueTime();
            long ms;
            if (t1 != null) {
                ms = now.getTime() - t1.getTime();
                if (ms < 0L) {
                    System.out.printf("Warning: the JWT issued-at time is invalid (in the future).\n");
                }
            }
            else {
                System.out.printf("Warning: the JWT has no issued-at time.\n");
            }

            Date t2 = claims.getExpirationTime();
            if (t2 != null) {
                ms = t2.getTime() - now.getTime(); // positive means still valid
                if (ms < 0L) {
                    System.out.printf("Warning: the JWT has expired.\n");
                }
                else {
                    long secsRemaining = ms/1000;
                    System.out.printf("The JWT is valid for %d more seconds.\n", secsRemaining);
                    System.out.printf("which is %s\n", DurationFormatUtils.formatDurationWords(ms, true, true));
                }
            }
            else {
                System.out.printf("Warning: the JWT has no expiry time.\n");
            }

            Date t3 = claims.getNotBeforeTime(); // optional
            if (t3 != null) {
                ms = now.getTime() - t3.getTime(); // positive means valid
                if (ms < 0L) {
                    System.out.printf("Warning: the JWT is not yet valid.\n");
                }
            }
        }

        else if (jwtAction == JwtAction.GENERATE) {
            String claimsJson = (String) this.options.get("c");
            if (claimsJson == null) {
                throw new IllegalStateException("Missing claims payload");
            }

            json = (JSONObject) JSONValue.parseWithException(claimsJson);

            JWTClaimsSet claims = JWTClaimsSet.parse(json);
            // The passed-in claimset needs to include issuer, subject, and audience if desired.
            // also, any other claims, either standard or custom.

            Date now = new Date();
            claims.setIssueTime(now);
            claims.setExpirationTime(getExpiryDate());

            String jti = (String) this.options.get("I");
            claims.setJWTID(jti);

            String privateKeyFile = (String) this.options.get("k");
            RSAPrivateKey privateKey = getPrivateKey(getPrivateKeyBytes(privateKeyFile));
            JWSSigner signer = new RSASSASigner(privateKey);
            JWSHeader.Builder builder = new JWSHeader.Builder(jwsAlg).type(TYP_JWT);

            String keyId = (String) this.options.get("i");
            if (keyId != null) builder.keyID(keyId);
            JWSHeader h = builder.build();
            SignedJWT signedJWT = new SignedJWT(h, claims);
            signedJWT.sign(signer);

            String jwt = signedJWT.serialize();
            System.out.println(jwt);
        }
    }

    public static void usage() {
        System.out.println("\nJwtTool: decode and optionally verify a JWT that was signed with RSA, or encode and RSA-sign a JWT.\n");
        System.out.printf("Parse:\n    java %s -p ...options...\n", JwtTool.class.getName());
        System.out.println("  options:");
        System.out.println("     -v                   verbose");
        System.out.println("     -t <token>           required. specify the JWT to parse");
        System.out.println("     -A <alg>             optional. Algorithm. Use RS256, RS384, or RS512. Default: RS256.");
        System.out.println("     -k <publickeyfile>   optional. specify the public key PEM file. If you want sig verification.\n");

        System.out.printf("Generate:\n    java %s -g ...options...\n", JwtTool.class.getName());
        System.out.println("  options:");
        System.out.println("     -v                   verbose");
        System.out.println("     -c <claimsjson>      optional. a json hash to include as claims in the generated JWT.");
        System.out.println("                          If you want iss, aud, and/or sub, you must place them within the json.");
        System.out.println("                          as well as any arbitrary additional claims.");
        System.out.println("     -i <keyid>           optional. The keyID (kid) to include in the JWT header.");
        System.out.println("     -I <jti>             optional. The JWT ID (jti) to include in the payload.");
        System.out.println("     -x <expiry>          optional. Expiry. Use 10s, 10m, 10h, 10d... for 10 seconds, minutes, hours, days..");
        System.out.println("     -A <alg>             optional. Algorithm. Use RS256, RS384, or RS512. Default: RS256.");
        System.out.println("     -k <privatekeyfile>  required. specify the private key (PEM) file used for signing.\n");
    }

    public static void main(String[] args) {
        try {
            JwtTool me = new JwtTool(args);
            me.run();
        }
        catch (java.lang.Exception exc1) {
            System.out.println("Exception:" + exc1.toString());
            exc1.printStackTrace();
            usage();
        }
    }

}
