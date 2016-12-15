// hashJwt.js
// ------------------------------------------------------------------
//
// Hash the JWT.
//
// created: Mon Dec  5 17:35:02 2016
// last saved: <2016-December-05 21:01:28>

var jwt = context.getVariable(properties.jwtvar);
var sha256 = crypto.getSHA256();
sha256.update(jwt);
var hashed = sha256.digest();
context.setVariable(properties.outputvar, hashed);
