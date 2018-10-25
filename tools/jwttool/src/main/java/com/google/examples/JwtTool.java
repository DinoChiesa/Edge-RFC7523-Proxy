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
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jwt.SignedJWT;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Hashtable;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import net.minidev.json.JSONObject;
import net.minidev.json.JSONStyleIdent;
import net.minidev.json.JSONValue;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.time.DurationFormatUtils;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.openssl.PEMDecryptorProvider;
import org.bouncycastle.openssl.PEMEncryptedKeyPair;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8DecryptorProviderBuilder;
import org.bouncycastle.openssl.jcajce.JcePEMDecryptorProviderBuilder;
import org.bouncycastle.operator.InputDecryptorProvider;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;

public class JwtTool {
    static {
        java.security.Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
    }
    private final static int DEFAULT_EXPIRY_IN_SECONDS = 300;

    private final static String optString = "pgvt:c:H:k:x:i:I:A:hs:TP:"; // getopt style
    private JwtAction jwtAction = JwtAction.NONE;
    private JWSAlgorithm jwsAlg;
    private final static JOSEObjectType TYP_JWT = new JOSEObjectType("JWT");

    public JwtTool (String[] args) throws java.lang.Exception {
        GetOpts(args, optString);
    }

    enum JwtAction { NONE, PARSE, GENERATE, HELP };

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
        else
            jwtAction = JwtAction.HELP;
    }


    private Date getExpiryDate() {
        Date current = new Date();
        Calendar cal = Calendar.getInstance();
        cal.setTime(current);

        int lifetimeInSeconds = DEFAULT_EXPIRY_IN_SECONDS;
        String expiry = (String) this.options.get("x");
        if (expiry != null) {
            lifetimeInSeconds = TimeResolver.resolveExpression(expiry).intValue();
        }
        cal.add(Calendar.SECOND, lifetimeInSeconds);
        Date then = cal.getTime();
        return then;
    }


    public static class KeyParseException extends Exception {
        private static final long serialVersionUID = 0L;

        KeyParseException(String message) {
            super(message);
        }

        KeyParseException(String message, Throwable th) {
            super(message, th);
        }
    }

    public static PrivateKey decodePrivateKey(String privateKeyString, String password) throws KeyParseException {
        try {
            JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");
            privateKeyString = reformIndents(privateKeyString);
            PEMParser pemParser = new PEMParser(new StringReader(privateKeyString));
            Object object = pemParser.readObject();
            if (object == null) {
                throw new KeyParseException("unable to read anything when decoding private key");
            }

            KeyPair kp = null;

            //LOGGER.info(String.format("decodePrivateKey, %s", object.getClass().getName()));
            if (object instanceof PKCS8EncryptedPrivateKeyInfo) {
                // produced by "openssl genpkey" or  the series of commands reqd to sign an ec key
                //LOGGER.info("decodePrivateKey, encrypted PrivateKeyInfo");
                PKCS8EncryptedPrivateKeyInfo pkcs8EncryptedPrivateKeyInfo = (PKCS8EncryptedPrivateKeyInfo) object;
                JceOpenSSLPKCS8DecryptorProviderBuilder decryptorProviderBuilder = new JceOpenSSLPKCS8DecryptorProviderBuilder();
                InputDecryptorProvider decryptorProvider = decryptorProviderBuilder.build(password.toCharArray());
                PrivateKeyInfo privateKeyInfo = pkcs8EncryptedPrivateKeyInfo.decryptPrivateKeyInfo(decryptorProvider);
                return (PrivateKey) converter.getPrivateKey(privateKeyInfo);
            }

            if (object instanceof PrivateKeyInfo) {
                // produced by openssl genpkey without encryption
                return (PrivateKey) converter.getPrivateKey((PrivateKeyInfo) object);
            }

            if (object instanceof PEMEncryptedKeyPair) {
                // produced by "openssl genrsa" or "openssl ec -genkey"
                // LOGGER.info("decodePrivateKey, encrypted keypair");
                PEMEncryptedKeyPair encryptedKeyPair = (PEMEncryptedKeyPair) object;
                PEMDecryptorProvider decryptorProvider = new JcePEMDecryptorProviderBuilder().build(password.toCharArray());
                kp = converter.getKeyPair(encryptedKeyPair.decryptKeyPair(decryptorProvider));
            }
            else if (object instanceof PEMKeyPair) {
                //LOGGER.info("decodePrivateKey, un-encrypted keypair");
                PEMKeyPair unencryptedKeyPair = (PEMKeyPair) object;
                kp = converter.getKeyPair(unencryptedKeyPair);
            }
            else {
                //LOGGER.error("decodePrivateKey, unknown object type {}", object.getClass().getName());
                throw new KeyParseException("unknown object type when decoding private key");
            }

            return (PrivateKey) kp.getPrivate();
        }
        catch (KeyParseException exc0) {
            throw exc0;
        }
        catch (Exception exc1) {
            throw new KeyParseException("cannot instantiate private key", exc1);
        }
    }

    private static String reformIndents(String s) {
        return s.trim().replaceAll("([\\r|\\n] +)","\n");
    }

    private static PublicKey decodePublicKey(String publicKeyString) throws KeyParseException {
        try {
            JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");
            publicKeyString = reformIndents(publicKeyString);
            PEMParser pemParser = new PEMParser(new StringReader(publicKeyString));
            Object object = pemParser.readObject();
            if (object == null) {
                throw new KeyParseException("unable to read anything when decoding public key");
            }
            return converter.getPublicKey((org.bouncycastle.asn1.x509.SubjectPublicKeyInfo) object);
        }
        catch (KeyParseException exc0) {
            throw exc0;
        }
        catch (Exception exc1) {
            throw new KeyParseException("cannot instantiate public key", exc1);
        }
    }

    public boolean isRSA(JWSAlgorithm jwsAlgorithm) {
        return jwsAlgorithm.toString().startsWith("RS");
    }
    public boolean isHMAC(JWSAlgorithm jwsAlgorithm) {
        return jwsAlgorithm.toString().startsWith("HS");
    }
    public boolean isECDSA(JWSAlgorithm jwsAlgorithm) {
        return jwsAlgorithm.toString().startsWith("ES");
    }

    public JWSVerifier getVerifier(JWSHeader jwsHeader) throws Exception {

        if (isRSA(jwsAlg)) {
            String pathToPublicKeyFile = (String) this.options.get("k");
            if (pathToPublicKeyFile != null) {
                String fileContent = readFileAsUtf8String(pathToPublicKeyFile);
                RSAPublicKey publicKey = (RSAPublicKey) decodePublicKey(fileContent);
                return new RSASSAVerifier(publicKey, jwsHeader.getCriticalParams());
            }
            System.out.printf("WARNING: No public key, not able to verify the signature.\n");
            return null;
        }

        if (isECDSA(jwsAlg)) {
            String pathToPublicKeyFile = (String) this.options.get("k");
            if (pathToPublicKeyFile != null) {
                String fileContent = readFileAsUtf8String(pathToPublicKeyFile);
                ECPublicKey publicKey = (ECPublicKey) decodePublicKey(fileContent);
                return new ECDSAVerifier(publicKey, jwsHeader.getCriticalParams());
            }
            System.out.printf("WARNING: No public key, not able to verify the signature.\n");
            return null;
        }

         if (isHMAC(jwsAlg)) {
            String secret = (String) this.options.get("s");
            if (secret!=null) {
                byte[] keyBytes = secret.getBytes(StandardCharsets.UTF_8);
                // NB: this will throw if the string is not at least 16 chars long
                return new MACVerifier(keyBytes, jwsHeader.getCriticalParams());
            }
            System.out.printf("WARNING: No secret, not able to verify the signature.\n");
            return null;
        }

        return null;
    }

    private String readFileAsUtf8String(String path) throws IOException {
        List<String> linelist = Files.readAllLines(Paths.get(path), StandardCharsets.UTF_8);
        String fileContent = StringUtils.join(linelist, "\n").trim();
        return fileContent;
    }

    public JWSSigner getSigner() throws Exception {
        if (isRSA(jwsAlg)) {
            String pathToPrivateKeyFile = (String) this.options.get("k");
            if (pathToPrivateKeyFile != null) {
                String fileContent = readFileAsUtf8String(pathToPrivateKeyFile);
                RSAPrivateKey privateKey = (RSAPrivateKey) decodePrivateKey(fileContent, (String) this.options.get("P"));
                return new RSASSASigner(privateKey);
            }
            System.out.printf("Warning: No private key, not able to sign the token.\n");
            return null;
        }

        if (isECDSA(jwsAlg)) {
            String pathToPrivateKeyFile = (String) this.options.get("k");
            if (pathToPrivateKeyFile != null) {
                String fileContent = readFileAsUtf8String(pathToPrivateKeyFile);
                ECPrivateKey privateKey = (ECPrivateKey) decodePrivateKey(fileContent, (String) this.options.get("P"));
                return new ECDSASigner(privateKey);
            }
            System.out.printf("Warning: No private key, not able to sign the token.\n");
            return null;
        }

        if (isHMAC(jwsAlg)) {
            String secret = (String) this.options.get("s");
            if (secret!=null) {
                byte[] keyBytes = secret.getBytes(StandardCharsets.UTF_8);
                // NB: this will throw if the string is not at least 16 chars long
                return new MACSigner(keyBytes);
            }
            System.out.printf("Warning: No secret key, not able to sign the token.\n");
            return null;
        }
        return null;
    }

    public void run() throws Exception {
        JSONObject json;
        maybeShowOptions();
        determineAction();
        if (jwtAction==JwtAction.NONE || jwtAction == JwtAction.HELP) {
            usage();
            return;
        }
        String alg = (String) this.options.get("A");
        if (alg== null)
          throw new IllegalStateException("Missing algorithm");

        jwsAlg = new JWSAlgorithm(alg);

        if (jwtAction == JwtAction.PARSE) {
            String token = (String) this.options.get("t");

            SignedJWT signedJwt = SignedJWT.parse(token);
            JWSHeader header = signedJwt.getHeader();
            json = header.toJSONObject();
            String prettyJson = json.toString(new JSONStyleIdent());
            System.out.println("header: " + prettyJson.replaceAll("\\\\/", "/"));

            JWTClaimsSet claims = signedJwt.getJWTClaimsSet();
            json = claims.toJSONObject();

            //System.out.println("payload: " + json.toString());
            prettyJson = json.toString(new JSONStyleIdent());
            System.out.println("payload: " + prettyJson.replaceAll("\\\\/", "/"));

            JWSVerifier verifier = getVerifier(header);

            if (verifier != null) {
                if (!signedJwt.verify(verifier)) {
                    System.out.printf("ERROR: The signature cannot be verified.\n");
                }
                else {
                    System.out.printf("INFO: The signature was verified.\n");
                }
                if (!header.getAlgorithm().toString().equals(jwsAlg.toString())) {
                    System.out.printf("INFO: Algorithm mismatch. (expected %s, actual %s)\n", jwsAlg.toString(), header.getAlgorithm().toString());
                }
            }

            Date now = new Date();
            Date t1 = claims.getIssueTime();
            long ms;
            if (t1 != null) {
                ms = now.getTime() - t1.getTime();
                if (ms < 0L) {
                    System.out.printf("WARNING: The JWT issued-at time is invalid (in the future).\n");
                }
            }
            else {
                System.out.printf("INFO: The JWT has no issued-at time.\n");
            }

            Date t2 = claims.getExpirationTime();
            if (t2 != null) {
                ms = t2.getTime() - now.getTime(); // positive means still valid
                if (ms < 0L) {
                    System.out.printf("INFO: The JWT has expired.\n");
                }
                else {
                    long secsRemaining = ms/1000;
                    System.out.printf("INFO: The JWT is valid for %d more seconds.\n", secsRemaining);
                    System.out.printf("INFO: which is %s\n", DurationFormatUtils.formatDurationWords(ms, true, true));
                }
            }
            else {
                System.out.printf("INFO: The JWT has no expiry time.\n");
            }

            Date t3 = claims.getNotBeforeTime(); // optional
            if (t3 != null) {
                ms = now.getTime() - t3.getTime(); // positive means valid
                if (ms < 0L) {
                    System.out.printf("ERROR: The JWT is not yet valid.\n");
                }
            }
        }

        else if (jwtAction == JwtAction.GENERATE) {
            String claimsJson = (String) this.options.get("c");
            if (claimsJson == null)
                throw new IllegalStateException("Missing claims payload");

            json = (JSONObject) JSONValue.parseWithException(claimsJson);
            JWTClaimsSet initialClaims = JWTClaimsSet.parse(json);
            JWTClaimsSet.Builder claimsBuilder = new JWTClaimsSet.Builder(initialClaims);

            // The passed-in claimset needs to include issuer, subject, and audience if desired.
            // also, any other claims, either standard or custom.

            if (this.options.get("T") == null)
                claimsBuilder.issueTime(new Date());

            if (this.options.get("x") != null)
                claimsBuilder.expirationTime(getExpiryDate());

            String jti = (String) this.options.get("I");
            if (jti!=null)
                claimsBuilder.jwtID(jti);

            JWSSigner signer = getSigner();

            JWSHeader.Builder headerBuilder = null;
            if (this.options.get("H") != null) {
              String headerJson = (String) this.options.get("H");
              json = (JSONObject) JSONValue.parseWithException(headerJson);
              if (!json.containsKey("alg")) {
                json.put("alg", (String)this.options.get("A"));
              }
              com.nimbusds.jose.JWSHeader initialHeader = com.nimbusds.jose.JWSHeader.parse(json);
              headerBuilder = new JWSHeader.Builder(initialHeader);
            }
            else {
              headerBuilder = new JWSHeader.Builder(jwsAlg).type(TYP_JWT);
            }

            String keyId = (String) this.options.get("i");
            if (keyId != null) headerBuilder.keyID(keyId);

            SignedJWT signedJWT = new SignedJWT(headerBuilder.build(), claimsBuilder.build());
            signedJWT.sign(signer);

            String jwt = signedJWT.serialize();
            System.out.println(jwt);
        }
    }

    public static void usage() {
        System.out.println("\nJwtTool: decode and optionally verify a JWT that was signed with RSA, HMAC or ECDSA,\nor encode and sign a JWT.\n");
        System.out.printf("Parse:\n    java %s -p ...options...\n", JwtTool.class.getName());
        System.out.println("  options:");
        System.out.println("     -v                   verbose");
        System.out.println("     -t <token>           required. the JWT to parse");
        System.out.println("     -A <alg>             optional. Algorithm. Use {RS,HS,ES}{256,384,512}. Default: RS256.");
        System.out.println("     -k <publickeyfile>   optional. the PEM file containing the public key. For RS* or ES.\n");
        System.out.println("     -s <secret>          optional. the shared secret. For HS* verification.\n");

        System.out.printf("Generate:\n    java %s -g ...options...\n", JwtTool.class.getName());
        System.out.println("  options:");
        System.out.println("     -v                   verbose");
        System.out.println("     -c <claimsjson>      optional. a json hash to include as claims in the payload of generated JWT.");
        System.out.println("                          If you want iss, aud, sub, etc, you must place them within this json.");
        System.out.println("     -H <headerjson>      optional. a json hash to include as claims in the header of the generated JWT.");
        System.out.println("                          If you want crit, cty, etc.. place them within this json.");
        System.out.println("     -i <keyid>           optional. The keyID (kid) to include in the JWT header.");
        System.out.println("     -I <jti>             optional. The JWT ID (jti) to include in the payload.");
        System.out.println("     -x <expiry>          optional. Expiry. Use 10s, 10m, 10h, 10d... for 10 seconds, minutes, hours, days..");
        System.out.println("     -T                   optional. Omit the issued-at time from the generated token.");
        System.out.println("     -A <alg>             required. Algorithm. Use {RS,HS,ES}{256,384,512}.");
        System.out.println("     -k <privkeyfile>     optional. the PEM file containing the private key. For RS* or ES.\n");
        System.out.println("     -s <secret>          optional. the shared secret. For HS* signing.\n");

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
