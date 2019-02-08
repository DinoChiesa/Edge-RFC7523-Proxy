// JwsTool.java
// ------------------------------------------------------------------
//
// This tool uses the Nimbus library to parse or generate a JWS
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

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.util.Base64URL;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import net.minidev.json.JSONObject;
import net.minidev.json.JSONStyleIdent;
import net.minidev.json.JSONValue;

public class JwsTool extends JOSEToolBase {
    private static final Pattern detachedJwsPattern = Pattern.compile("^([^\\.]+)\\.\\.([^\\.]+)$");
    private final static String optString = "VGb:A:k:P:s:H:i:p:f:Dhv"; // getopt style

    public JwsTool (String[] args) throws java.lang.Exception {
        super(args, optString);
    }

    public void run() throws Exception {
        JSONObject json;
        maybeShowOptions();
        determineAction();
        if (toolAction==ToolAction.NONE || toolAction == ToolAction.HELP) {
            usage();
            return;
        }
        String alg = (String) this.options.get("A");

        if (toolAction == ToolAction.VERIFY) {
            String blob = (String) this.options.get("b");

            String contentFilename = (String) this.options.get("f");
            if (contentFilename != null) {
                Matcher m = detachedJwsPattern.matcher(blob);
                if (!m.find())
                    throw new IllegalStateException("Missing algorithm");
                String encodedPayload = Base64URL.encode(readAllBytes(Files .newInputStream(Paths.get(contentFilename)))).toString();
                blob = m.group(1) + "." + encodedPayload + "."+ m.group(2);
            }

            JWSObject jwsObject = JWSObject.parse(blob);
            JWSHeader header = jwsObject.getHeader();
            json = header.toJSONObject();
            String prettyJson = json.toString(new JSONStyleIdent());
            System.out.println("header: " + prettyJson.replaceAll("\\\\/", "/"));

            JWSVerifier verifier = getVerifier(header);

            if (verifier != null) {
                if (!jwsObject.verify(verifier)) {
                    System.out.printf("ERROR: The signature cannot be verified.\n");
                }
                else {
                    System.out.printf("INFO: The signature was verified.\n");
                }
                if (alg != null) {
                    JWSAlgorithm jwsAlg = new JWSAlgorithm(alg);

                    if (jwsAlg != null) {
                        if (!header.getAlgorithm().toString().equals(jwsAlg.toString())) {
                            System.out.printf("INFO: Algorithm mismatch. (expected %s, actual %s)\n", jwsAlg.toString(), header.getAlgorithm().toString());
                        }
                    }
                }
            }
        }

        else if (toolAction == ToolAction.GENERATE) {
            if (alg== null)
                throw new IllegalStateException("Missing algorithm");

            JWSAlgorithm jwsAlg = new JWSAlgorithm(alg);

            JWSSigner signer = getSigner(jwsAlg);
            JWSHeader.Builder headerBuilder = null;
            if (this.options.get("H") != null) {
              String headerJson = (String) this.options.get("H");
              json = (JSONObject) JSONValue.parseWithException(headerJson);
              if (!json.containsKey("alg")) {
                  json.put("alg", alg);
              }
              com.nimbusds.jose.JWSHeader initialHeader = com.nimbusds.jose.JWSHeader.parse(json);
              headerBuilder = new JWSHeader.Builder(initialHeader);
            }
            else {
              headerBuilder = new JWSHeader.Builder(jwsAlg).type(TYP_JOSE);
            }

            String keyId = (String) this.options.get("i");
            if (keyId != null) headerBuilder.keyID(keyId);

            String payload = (String) this.options.get("p");
            String contentFilename = (String) this.options.get("f");
            if ((payload != null) && (contentFilename != null))
                throw new IllegalStateException("Use only one of -p and -f");

            if ((payload == null) && (contentFilename == null))
                throw new IllegalStateException("Use only one of -p and -f");

            JWSObject jwsObject = new JWSObject(headerBuilder.build(),
                                                (payload!=null) ? new Payload(payload) :
                                                new Payload(readAllBytes(Files .newInputStream(Paths.get(contentFilename)))) );
            jwsObject.sign(signer);

            Boolean wantDetach = (Boolean) this.options.get("D");
            if (wantDetach != null && wantDetach) {
                System.out.printf("%s..%s\n",
                                  jwsObject.getHeader().toBase64URL().toString(),
                                  jwsObject.getSignature().toString());
            }
            else {
                String blob = jwsObject.serialize();
                System.out.println(blob);
            }
        }
    }

    public static byte[] readAllBytes(InputStream is) throws IOException {
        ByteArrayOutputStream os = new ByteArrayOutputStream();
        byte[] buffer = new byte[1024];
        for (int len = is.read(buffer); len != -1; len = is.read(buffer)) {
            os.write(buffer, 0, len);
        }
        return os.toByteArray();
    }

    public static void usage() {
        System.out.println("\nJwsTool: decode and verify a JWS that was signed with HMAC, RSASSA-PKCS1, RSASSA-PSS, ECDSA,\nor encode and sign (generate) a JWS with any of those algorithms.\n");
        System.out.printf("Verify:\n    java %s -V ...options...\n", JwtTool.class.getName());
        System.out.println("  options:");
        System.out.println("     -v                   verbose");
        System.out.println("     -b <blob>            required. the JWS blob to parse");
        System.out.println("     -f                   optional. file containing detached payload content.");
        System.out.println("     -A <alg>             optional. Algorithm. Use {RS,HS,ES,PS}{256,384,512}. Default: RS256.");
        System.out.println("     -k <publickeyfile>   optional. the PEM file containing the public key. For RS* or ES.\n");
        System.out.println("     -s <secret>          optional. the shared secret. For HS* verification.\n");

        System.out.printf("Generate:\n    java %s -G ...options...\n", JwtTool.class.getName());
        System.out.println("  options:");
        System.out.println("     -v                   verbose");
        System.out.println("     -H <headerjson>      optional. a json hash to include as claims in the header of the generated JWT.");
        System.out.println("                          If you want crit, cty, etc.. place them within this json.");
        System.out.println("     -i <keyid>           optional. The keyID (kid) to include in the JWS header.");
        System.out.println("     -p <payload>         optional. The JWS payload string.");
        System.out.println("     -f <file>            optional. The file to use for payload content.");
        System.out.println("     -D                   optional. Detach the signed payload.");
        System.out.println("     -A <alg>             required. Algorithm. Use {RS,HS,ES,PS}{256,384,512}.");
        System.out.println("     -k <privkeyfile>     optional. the PEM file containing the private key. For RS*, PS*, or ES*.\n");
        System.out.println("     -P <privkeypwd>      optional. the password for an encrypted private key PEM file.\n");
        System.out.println("     -s <secret>          optional. the shared secret. For HS* signing.\n");

    }

    public static void main(String[] args) {
        try {
            JwsTool me = new JwsTool(args);
            me.run();
        }
        catch (java.lang.Exception exc1) {
            System.out.println("Exception:" + exc1.toString());
            exc1.printStackTrace();
            usage();
        }
    }

}
