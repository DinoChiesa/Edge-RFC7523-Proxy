#!/bin/bash
# -*- mode:shell-script; coding:utf-8; -*-
#
# Created: <Mon Dec  5 17:51:55 2016>
# Last Updated: <2016-December-14 21:03:02>
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
  echo "  Check a JWT for use with the jwt2token API proxy. "
  echo "  Uses the JwtTool Java program."
  echo "usage: "
  echo "  $CMD [options] "
  echo "options: "
  echo "  -t token     the jwt to check."
  echo "  -k pubkey    public key file."
  echo
  exit 1
}


while getopts "hk:t:" opt; do
  case $opt in
    h) usage ;;
    k) publicKey=$OPTARG ;;
    t) token=$OPTARG ;;
    *) echo "unknown arg" && usage ;;
  esac
done

####################################################################

[[ ! -f "${publicKey}" ]] && echo "you must provide a public key" && echo && usage

echo
echo

java -classpath "$tooldir/jwt-tool.jar:$tooldir/lib/*" com.google.examples.JwtTool -p -k ${publicKey} -t "${token}"

echo



