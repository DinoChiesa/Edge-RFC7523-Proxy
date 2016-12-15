// base64.js
// ------------------------------------------------------------------
//
// Bas64 encoder and decoder
//
// created: Sat Feb 20 12:30:51 2016
// last saved: <2016-March-14 10:42:09>

(function (){
  var Base64 = {
        decode : function (input) {
          // Takes a base 64 encoded string "input", strips any "=" or
          // "==" padding off it and converts its base 64 numerals into
          // regular integers (using a string as a lookup table). These
          // are then written out as 6-bit binary numbers and concatenated
          // together. The result is split into 8-bit sequences and these
          // are converted to string characters, which are concatenated
          // and output.

          // The index/character relationship in the following string acts
          // as a lookup table to convert from base 64 numerals to
          // JavaScript integers.
          var swaps = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
              ob = "",
              output = "",
              tb = "",
              i, L;

          input = input.trim();
          input = input.replace("=",""); // strip padding

          for (i=0, L = input.length; i < L; i++) {
            tb = swaps.indexOf(input.charAt(i)).toString(2);
            while (tb.length < 6) {
              // Add significant zeroes
              tb = "0"+tb;
            }
            while (tb.length > 6) {
              // Remove significant bits
              tb = tb.substring(1);
            }
            ob += tb;
            while (ob.length >= 8) {
              output += String.fromCharCode(parseInt(ob.substring(0,8),2));
              ob = ob.substring(8);
            }
          }

          return output;
        },
        encode : function (input) {
          // Converts each character in the input to its Unicode number,
          // then writes out the Unicode numbers in binary, one after
          // another, into a string.  This string is then split up at
          // every 6th character, these substrings are then converted back
          // into binary integers and are used to subscript the "swaps"
          // array.  Since this would create HUGE strings of 1s and 0s,
          // the distinct steps above are actually interleaved in the code
          // below (ie. the long binary string, called "input_binary",
          // gets processed while it is still being created, so that it
          // never gets too big (in fact, it stays under 13 characters
          // long no matter what).

          // The indices of this array provide the map from numbers to
          // base64.
          var swaps = ["A","B","C","D","E","F","G","H","I","J","K","L","M",
                       "N","O","P","Q","R","S","T","U","V","W","X","Y","Z",
                       "a","b","c","d","e","f","g","h","i","j","k","l","m",
                       "n","o","p","q","r","s","t","u","v","w","x","y","z",
                       "0","1","2","3","4","5","6","7","8","9","+","/"],

              tb, ib = "",
              output = "",
              i, L;

          if (input && input.length) {
            for (i=0, L = input.length; i < L; i++) {
              // Turn the next character of input into astring of 8-bit binary
              tb = input.charCodeAt(i).toString(2);
              while (tb.length < 8) {
                tb = "0"+tb;
              }
              // Stick this string on the end of the previous 8-bit binary
              // strings to get one big concatenated binary representation
              ib = ib + tb;
              // Remove all 6-bit sequences from the start of the
              // concatenated binary string, convert them to a base 64
              // character and append to output.  Doing this here prevents
              // ib from getting massive
              while (ib.length >= 6) {
                output = output + swaps[parseInt(ib.substring(0,6),2)];
                ib = ib.substring(6);
              }
            }
            // Handle any necessary padding
            if (ib.length == 4) {
              tb = ib + "00";
              output += swaps[parseInt(tb,2)] + "=";
            }
            if (ib.length == 2) {
              tb = ib + "0000";
              output += swaps[parseInt(tb,2)] + "==";
            }
          }
          return output;
        }
      };

  // export into the global namespace
  if (typeof exports === "object" && exports) {
    // works for nodejs
    exports.B64 = Base64;
  }
  else {
    // works in rhino
    var globalScope = (function(){ return this; }).call(null);
    globalScope.B64 = Base64;
  }

}());
