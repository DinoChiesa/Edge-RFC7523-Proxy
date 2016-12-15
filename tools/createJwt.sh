#!/bin/bash
# -*- mode:shell-script; coding:utf-8; -*-
#
# Created: <Mon Dec  5 17:51:55 2016>
# Last Updated: <2016-December-14 20:59:52>
#

scriptdir="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
tooldir=${scriptdir}/jwttool/target
privateKey=""
issuer=""
expiry=300
scope="urn://www.apigee.com/apitechforum.readonly"
audience="urn://www.apigee.com/apitechforum/token"

function usage() {
  local CMD=`basename $0`
  echo "$CMD: "
  echo "  Create a JWT for use with the jwt2token API proxy. "
  echo "  Uses the JwtTool Java program."
  echo "usage: "
  echo "  $CMD [options] "
  echo "options: "
  echo "  -k privkey   private key file."
  echo "  -i iss       issuer claim for the JWT."
  echo "  -e NNN       lifetime of the JWT in seconds. default: 300"
  echo "  -a audience  audience. Defaults to ${audience}"
  echo "  -s scope     scope. defaults to ${scope}"
  echo
  exit 1
}


while getopts "hk:i:e:a:s:" opt; do
  case $opt in
    h) usage ;;
    k) privateKey=$OPTARG ;;
    i) issuer=$OPTARG ;;
    e) expiry=$OPTARG ;;
    a) audience=$OPTARG ;;
    s) scope=$OPTARG ;;
    *) echo "unknown arg" && usage ;;
  esac
done

####################################################################

[[ ! -f "${privateKey}" ]] && echo "you must provide a private key" && echo && usage
[[ -z "${issuer}" ]] && echo "you must provide an issuer" && echo && usage

claims=$'{\n'
claims+=$'   "iss":"'
claims+=${issuer}
claims+=$'",\n'
claims+=$'   "scope":"'
claims+=${scope}
claims+=$'",\n'
claims+=$'   "aud":"'
claims+=${audience}
claims+=$'"\n}'

echo "claims: "
echo "${claims}"

jwt=$(java -classpath "$tooldir/jwt-tool.jar:$tooldir/lib/*" com.google.examples.JwtTool -g -k ${privateKey} -c "${claims}" -x ${expiry})

echo
echo
echo "The JWT is: "
echo $jwt
echo
echo
echo "To use the JWT:"
echo
echo "curl -X POST -H content-type:application/x-www-form-urlencoded \\"
echo "    https://ORGNAME-ENVNAME.apigee.net/rfc7523/jwt2token/token \\"
printf "    -d  'grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion=%s'" $jwt
  



