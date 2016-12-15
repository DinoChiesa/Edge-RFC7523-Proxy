// extractIssuer.js
// ------------------------------------------------------------------
//
// Split a JWT, and without validating it, extract the issuer property in the claims.
//
// created: Mon Dec  5 17:35:02 2016
// last saved: <2016-December-05 21:01:20>

var jwt = context.getVariable(properties.jwtvar);
var parts = jwt.split('.');
if (parts.length != 3) {
  throw new Error("invalid JWT - incorrect number of parts. Expected 3, found " + parts.length );
}
var claims = JSON.parse(B64.decode(parts[1]));

if ( ! claims.iss) {
  throw new Error("invalid JWT - no issuer");
}
context.setVariable(properties.outputvar, claims.iss);
