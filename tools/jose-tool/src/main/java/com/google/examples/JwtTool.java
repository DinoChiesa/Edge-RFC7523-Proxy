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

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import java.util.Calendar;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import net.minidev.json.JSONObject;
import net.minidev.json.JSONStyleIdent;
import net.minidev.json.JSONValue;
import org.apache.commons.lang3.time.DurationFormatUtils;

public class JwtTool extends JOSEToolBase {
  private static final int DEFAULT_EXPIRY_IN_SECONDS = 300;
  private static final String optString = "VGvt:c:H:k:P:s:x:i:I:A:hT"; // getopt style

  public JwtTool(String[] args) throws java.lang.Exception {
    super(args, optString);
  }

  public static class TimeResolver {
    private static final Pattern expiryPattern =
        Pattern.compile("^([1-9][0-9]*)(ms|s|m|h|d|w|)$", Pattern.CASE_INSENSITIVE);
    private static final Map<String, Long> timeMultipliers;

    static {
      Map<String, Long> m1 = new HashMap<String, Long>();
      m1.put("s", 1L);
      m1.put("m", 60L);
      m1.put("h", 60L * 60);
      m1.put("d", 60L * 60 * 24);
      m1.put("w", 60L * 60 * 24 * 7);
      // m1.put("y", 60*60*24*365*1000);
      timeMultipliers = m1;
    }

    private static final String defaultUnit = "s";

    public static Date getExpiryDate(String expiresInString) {
      Calendar cal = Calendar.getInstance();
      Long milliseconds = resolveExpression(expiresInString);
      Long seconds = milliseconds / 1000;
      int secondsToAdd = seconds.intValue();
      if (secondsToAdd <= 0) return null; /* no expiry */
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
        if (key.equals("")) key = defaultUnit;
        return Long.parseLong(m.group(1), 10) * timeMultipliers.get(key);
      }
      return -1L;
    }
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

  public void run() throws Exception {
    JSONObject json;
    maybeShowOptions();
    determineAction();
    if (toolAction == ToolAction.NONE || toolAction == ToolAction.HELP) {
      usage();
      return;
    }
    String alg = (String) this.options.get("A");
    if (toolAction == ToolAction.VERIFY) {
      String token = (String) this.options.get("t");

      SignedJWT signedJwt = SignedJWT.parse(token);
      JWSHeader header = signedJwt.getHeader();
      json = header.toJSONObject();
      String prettyJson = json.toString(new JSONStyleIdent());
      System.out.println("header: " + prettyJson.replaceAll("\\\\/", "/"));

      JWTClaimsSet claims = signedJwt.getJWTClaimsSet();
      json = claims.toJSONObject();

      // System.out.println("payload: " + json.toString());
      prettyJson = json.toString(new JSONStyleIdent());
      System.out.println("payload: " + prettyJson.replaceAll("\\\\/", "/"));

      JWSVerifier verifier = getVerifier(header);

      if (verifier != null) {
        if (!signedJwt.verify(verifier)) {
          System.out.printf("ERROR: The signature cannot be verified.\n");
        } else {
          System.out.printf("INFO: The signature was verified.\n");
        }
        if (alg != null) {
          JWSAlgorithm jwsAlg = new JWSAlgorithm(alg);

          if (jwsAlg != null) {
            if (!header.getAlgorithm().toString().equals(jwsAlg.toString())) {
              System.out.printf(
                  "INFO: Algorithm mismatch. (expected %s, actual %s)\n",
                  jwsAlg.toString(), header.getAlgorithm().toString());
            }
          }
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
      } else {
        System.out.printf("INFO: The JWT has no issued-at time.\n");
      }

      Date t2 = claims.getExpirationTime();
      if (t2 != null) {
        ms = t2.getTime() - now.getTime(); // positive means still valid
        if (ms < 0L) {
          System.out.printf("INFO: The JWT has expired.\n");
        } else {
          long secsRemaining = ms / 1000;
          System.out.printf("INFO: The JWT is valid for %d more seconds.\n", secsRemaining);
          System.out.printf(
              "INFO: which is %s\n", DurationFormatUtils.formatDurationWords(ms, true, true));
        }
      } else {
        System.out.printf("INFO: The JWT has no expiry time.\n");
      }

      Date t3 = claims.getNotBeforeTime(); // optional
      if (t3 != null) {
        ms = now.getTime() - t3.getTime(); // positive means valid
        if (ms < 0L) {
          System.out.printf("ERROR: The JWT is not yet valid.\n");
        }
      }
    } else if (toolAction == ToolAction.GENERATE) {
      if (alg == null) throw new IllegalStateException("Missing algorithm");
      JWSAlgorithm jwsAlg = new JWSAlgorithm(alg);

      String claimsJson = (String) this.options.get("c");
      if (claimsJson == null) throw new IllegalStateException("Missing claims payload");

      json = (JSONObject) JSONValue.parseWithException(claimsJson);
      JWTClaimsSet initialClaims = JWTClaimsSet.parse(json);
      JWTClaimsSet.Builder claimsBuilder = new JWTClaimsSet.Builder(initialClaims);

      // The passed-in claimset needs to include issuer, subject, and audience if desired.
      // also, any other claims, either standard or custom.

      if (this.options.get("T") == null) claimsBuilder.issueTime(new Date());

      if (this.options.get("x") != null) claimsBuilder.expirationTime(getExpiryDate());

      String jti = (String) this.options.get("I");
      if (jti != null) claimsBuilder.jwtID(jti);

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
      } else {
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
    System.out.println(
        "\nJwtTool: decode and verify a JWT that was signed with HMAC, RSASSA-PKCS1, RSASSA-PSS, ECDSA,\nor encode and sign (generate) a JWT with any of those algorithms.\n");
    System.out.printf("Verify:\n    java %s -V ...options...\n", JwtTool.class.getName());
    System.out.println("  options:");
    System.out.println("     -v                   verbose");
    System.out.println("     -t <token>           required. the JWT to parse");
    System.out.println(
        "     -A <alg>             optional. Algorithm. Use {RS,HS,ES,PS}{256,384,512}. Default: RS256.");
    System.out.println(
        "     -k <publickeyfile>   optional. the PEM file containing the public key. For RS*, PS*, or ES*.\n");
    System.out.println(
        "     -s <secret>          optional. the shared secret. For HS* verification.\n");

    System.out.printf("Generate:\n    java %s -G ...options...\n", JwtTool.class.getName());
    System.out.println("  options:");
    System.out.println("     -v                   verbose");
    System.out.println(
        "     -c <claimsjson>      optional. a json hash to include as claims in the payload of generated JWT.");
    System.out.println(
        "                          If you want iss, aud, sub, etc, you must place them within this json.");
    System.out.println(
        "     -H <headerjson>      optional. a json hash to include as claims in the header of the generated JWT.");
    System.out.println(
        "                          If you want crit, cty, etc.. place them within this json.");
    System.out.println(
        "     -i <keyid>           optional. The keyID (kid) to include in the JWT header.");
    System.out.println(
        "     -I <jti>             optional. The JWT ID (jti) to include in the payload.");
    System.out.println(
        "     -x <expiry>          optional. Expiry. Use 10s, 10m, 10h, 10d... for 10 seconds, minutes, hours, days..");
    System.out.println(
        "     -T                   optional. Omit the issued-at time from the generated token.");
    System.out.println(
        "     -A <alg>             required. Algorithm. Use {RS,HS,ES,PS}{256,384,512}.");
    System.out.println(
        "     -k <privkeyfile>     optional. the PEM file containing the private key. For RS*, PS*, or ES*.\n");
    System.out.println(
        "     -P <privkeypwd>      optional. the password for an encrypted private key PEM file.\n");
    System.out.println("     -s <secret>          optional. the shared secret. For HS* signing.\n");
  }

  public static void main(String[] args) {
    try {
      JwtTool me = new JwtTool(args);
      me.run();
    } catch (java.lang.Exception exc1) {
      System.out.println("Exception:" + exc1.toString());
      exc1.printStackTrace();
      usage();
    }
  }
}
