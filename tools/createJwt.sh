#!/bin/bash
# -*- mode:shell-script; coding:utf-8; -*-
#
# Created: <Mon Dec  5 17:51:55 2016>
# Last Updated: <2018-March-15 09:44:33>
#

scriptdir="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
tooldir=${scriptdir}/jwttool/target
privateKey=""
issuer=""
orgname="ORGNAME"
envname="ENVNAME"
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
  echo "  -k privkey   Required. private key file."
  echo "  -i iss       Required. issuer claim for the JWT. Use the client_id."
  echo "  -x NNN       Optional. lifetime of the JWT in seconds. default: 300"
  echo "  -e env       Optional. environment name. Used to emit example curl call"
  echo "  -o org       Optional. organization name. Used to emit example curl call"
  echo "  -a audience  Optional. audience. Defaults to ${audience}"
  echo "  -s scope     Optional. scope. defaults to ${scope}"
  echo
  exit 1
}

while getopts "hk:i:x:e:o:a:s:" opt; do
  case $opt in
    h) usage ;;
    k) privateKey=$OPTARG ;;
    i) issuer=$OPTARG ;;
    x) expiry=$OPTARG ;;
    e) envname=$OPTARG ;;
    o) orgname=$OPTARG ;;
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

[[ ! -f "$tooldir/jwt-tool.jar" ]] && $(cd jwttool; mvn clean package; cd ..)

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
echo "    https://${orgname}-${envname}.apigee.net/rfc7523/jwt2token/token \\"
printf "    -d  'grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion=%s'" $jwt
  
