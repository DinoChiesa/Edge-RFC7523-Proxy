// JOSEToolBase.java
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

public abstract class JOSEToolBase {
    static {
        java.security.Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
    }

    protected enum ToolAction { NONE, VERIFY, GENERATE, HELP };
    protected ToolAction toolAction = ToolAction.NONE;
    protected final static JOSEObjectType TYP_JWT = new JOSEObjectType("JWT");
    protected final static JOSEObjectType TYP_JOSE = new JOSEObjectType("JOSE");

    protected Hashtable<String, Object> options = new Hashtable<String, Object> ();

    protected JOSEToolBase(String[] args, String optString) throws java.lang.Exception {
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

    protected static ArrayList<String> asOptionsList(Object o) {
        if (o instanceof ArrayList<?>) {
            return (ArrayList<String>) o;
        }

        ArrayList<String> list = new ArrayList<String>();

        if (o instanceof String) {
            list.add((String)o);

        }
        return list;
    }

    protected void maybeShowOptions() {
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

    protected void determineAction() {
        Boolean verify = (Boolean) this.options.get("V");
        Boolean generate = (Boolean) this.options.get("G");
        if (verify != null && verify && generate==null) {
            toolAction = ToolAction.VERIFY;
        }
        else if (generate != null && generate && verify == null) {
            toolAction = ToolAction.GENERATE;
        }
        else
            toolAction = ToolAction.HELP;
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

    public static PublicKey decodePublicKey(String publicKeyString) throws KeyParseException {
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
        return jwsAlgorithm.toString().startsWith("RS") || jwsAlgorithm.toString().startsWith("PS") ;
    }
    public boolean isHMAC(JWSAlgorithm jwsAlgorithm) {
        return jwsAlgorithm.toString().startsWith("HS");
    }
    public boolean isECDSA(JWSAlgorithm jwsAlgorithm) {
        return jwsAlgorithm.toString().startsWith("ES");
    }

    public JWSVerifier getVerifier(JWSHeader jwsHeader) throws Exception {
      JWSAlgorithm jwsAlg = jwsHeader.getAlgorithm();
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

    public JWSSigner getSigner(JWSAlgorithm jwsAlg) throws Exception {
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

}
