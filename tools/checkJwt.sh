#!/bin/bash
# -*- mode:shell-script; coding:utf-8; -*-
#
# Created: <Mon Dec  5 17:51:55 2016>
# Last Updated: <2019-December-03 15:21:06>
#

scriptdir="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
tooldir=jose-tool
tooltargetdir="${scriptdir}/${tooldir}/target"
toolversion=20190207
tooljar="$tooltargetdir/apigee-jose-tool-$toolversion.jar"
privateKey=""
issuer=""
expiry=300
scope="urn://www.apigee.com/apitechforum.readonly"
audience="urn://www.apigee.com/apitechforum/token"

function usage() {
  local CMD=`basename $0`
  echo "$CMD: "
  echo "  Check a JWT for use with the rfc7523/oauth API proxy. "
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


jwt=$(java -classpath "$tooljar:$tooltargetdir/lib/*" com.google.examples.JwtTool -p -k ${publicKey} -t "${token}")

echo



