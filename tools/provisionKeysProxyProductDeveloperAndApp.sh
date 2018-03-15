#!/bin/bash
# -*- mode:shell-script; coding:utf-8; -*-
#
# provisionProxyProductDeveloperAndApp.sh
#
# A bash script for provisioning a proxy, a product, a developer and a developer app on
# an organization in the Apigee Edge Gateway. This supports the RFC7523 example. 
#
# Last saved: <2018-March-15 10:54:06>
#

verbosity=2
orgname=""
envname="test"
apiproductname="Rfc7523-Example"
developerEmail="rfc7523-example-dev@example.com"
nametag="rfc7523"
proxyname="rfc7523"
requiredcache="rfc7523-cache"
defaultmgmtserver="https://api.enterprise.apigee.com"
netrccreds=0
want_deploy=1
resetAll=0
credentials=""
eightDaysInMillseconds=691200000
TAB=$'\t'
scriptdir="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
apiproxydir="$(cd "${scriptdir}/../apiproxy";pwd)"

usage() {
  local CMD=`basename $0`
  echo "$CMD: "
  echo "  Creates keys, imports and deploys a proxy, creates an API Product, a Developer and a"
  echo "  Developer app for the API Product.  Emits the client id and secret."
  echo "  Uses the curl utility."
  echo "usage: "
  echo "  $CMD [options] "
  echo "options: "
  echo "  -m url    optional. the base url for the mgmt server."
  echo "  -o org    required. the org to use."
  echo "  -e env    optional. the environment to use. default: ${envname}"
  echo "  -u creds  optional. http basic authn credentials for the API calls."
  echo "  -n        optional. tells curl to use .netrc to retrieve credentials"
  echo "  -d email  optional. developer email.  Default: ${developerEmail}"
  echo "  -p prod   optional. api product name.  Default: ${apiproductname}"
  echo "  -r        optional. tells the script to reset everything: delete app, developer, product, proxy."
  echo "  -q        quiet; decrease verbosity by 1"
  echo "  -S        optional. skip import and deployment of the proxy."
  echo "  -v        verbose; increase verbosity by 1"
  echo
  echo "Current parameter values:"
  echo "  mgmt api url: $defaultmgmtserver"
  echo "     verbosity: $verbosity"
  echo
  exit 1
}

## function MYCURL
## Print the curl command, omitting sensitive parameters, then run it.
## There are side effects:
## 1. puts curl output into file named ${CURL_OUT}. If the CURL_OUT
##    env var is not set prior to calling this function, it is created
##    and the name of a tmp file in /tmp is placed there.
## 2. puts curl http_status into variable CURL_RC
MYCURL() {
  [[ -z "${CURL_OUT}" ]] && CURL_OUT=`mktemp /tmp/apigee-edge-provision-demo.curl.out.XXXXXX`
  [[ -f "${CURL_OUT}" ]] && rm ${CURL_OUT}
  [[ $verbosity -gt 0 ]] && echo "curl $@"

  # run the curl command
  CURL_RC=`curl $credentials -s -w "%{http_code}" -o "${CURL_OUT}" "$@"`
  [[ $verbosity -gt 0 ]] && echo "==> ${CURL_RC}"
}

CleanUp() {
  [[ -f ${CURL_OUT} ]] && rm -rf ${CURL_OUT}
}

echoerror() { echo "$@" 1>&2; }

choose_mgmtserver() {
  local name
  echo
  read -p "  Which mgmt server (${defaultmgmtserver}) :: " name
  name="${name:-$defaultmgmtserver}"
  mgmtserver=$name
  echo "  mgmt server = ${mgmtserver}"
}


choose_credentials() {
  local username password

  read -p "username for Edge org ${orgname} at ${mgmtserver} ? (blank to use .netrc): " username
  echo
  if [[ "$username" = "" ]] ; then  
    credentials="-n"
  else
    echo -n "Org Admin Password: "
    read -s password
    echo
    credentials="-u ${username}:${password}"
  fi
}

maybe_ask_password() {
  local password
  if [[ ${credentials} =~ ":" ]]; then
    credentials="-u ${credentials}"
  else
    echo -n "password for ${credentials}?: "
    read -s password
    echo
    credentials="-u ${credentials}:${password}"
  fi
}



check_org() {
  [[ $verbosity -gt 0 ]] && echo "checking org ${orgname}..."
  MYCURL -X GET  ${mgmtserver}/v1/o/${orgname}
  if [[ ${CURL_RC} -eq 200 ]]; then
    check_org=0
  else
    check_org=1
  fi
}


random_string() {
  local rand_string
  rand_string=$(cat /dev/urandom |  LC_CTYPE=C  tr -cd '[:alnum:]' | head -c 10)
  echo ${rand_string}
}


verify_or_create_cache() {
  local wantedcache existingcache ttl c exists

  [[ $verbosity -gt 0 ]] && echo "check for existing caches..."
  MYCURL -X GET ${mgmtserver}/v1/o/${orgname}/e/${envname}/caches/
  if [[ ${CURL_RC} -ne 200 ]]; then
    echo 
    echoerror "Cannot retrieve caches for that environment..."
    echo
    echo CURL_RC = ${CURL_RC}
    echo
    cat ${CURL_OUT}
    CleanUp
    exit 1
  fi

  c=$(cat ${CURL_OUT} | grep "\[" | sed -E 's/[]",[]//g')
  IFS=' '; declare -a cachearray=($c)

  # trim spaces
  wantedcache="$(echo "${requiredcache}" | tr -d '[[:space:]]')"
  exists=0
  for i in "${!cachearray[@]}" ; do
    existingcache="${cachearray[i]}"
    echo "found cache: ${existingcache}"
    if [[ "$wantedcache" = "$existingcache" ]] ; then
      exists=1
    fi
  done

  if [[ $exists -eq 0 ]]; then 
    echo "creating the cache \"$wantedcache\"..."
    MYCURL -X POST -H Content-type:application/json \
      "${mgmtserver}/v1/o/${orgname}/e/${envname}/caches?name=$wantedcache" \
      -d '{
        "compression": {
          "minimumSizeInKB": 1024
        },
        "distributed" : true,
        "description": "cache supporting nonce mgmt in the HttpSig proxy",
        "diskSizeInMB": 0,
        "expirySettings": {
          "timeoutInSec" : {
            "value" : 86400
          },
          "valuesNull": false
        },
        "inMemorySizeInKB": 8000,
        "maxElementsInMemory": 3000000,
        "maxElementsOnDisk": 1000,
        "overflowToDisk": false,
        "persistent": false,
        "skipCacheIfElementSizeInKBExceeds": "12"
      }'
    if [[ ${CURL_RC} -eq 409 ]]; then
      ## should have caught this above, but just in case
      echo
      echo "That cache already exists."
    elif [ ${CURL_RC} -ne 201 ]; then
      echo
      echoerror "failed creating the cache."
      echo
      echo CURL_RC = ${CURL_RC}
      echo
      cat ${CURL_OUT}
      echo
      CleanUp
      echo
      exit 1
    fi
  else
      [[ $verbosity -gt 0 ]] && echo "A-OK: the needed cache, $wantedcache, exists..."
  fi
}


produce_proxy_zip() {
    local curdir=$(pwd) zipout r=$(random_string) destzip
    destzip="/tmp/${nametag}.apiproxy.${r}.zip"
    
    if [[ -f "${destzip}" ]]; then
        [[ $verbosity -gt 0 ]] && echo "removing the existing zip..."
        rm -rf "${destzip}"
    fi
    [[ $verbosity -gt 0 ]] && echo "Creating the zip ${destzip}..."

    cd ${apiproxydir}
    cd ..

    zipout=$(zip -r "$destzip" apiproxy -x "*/*.*~" -x "*/.tern-port"  -x "*/.DS_Store" -x "*/Icon*" -x "*/#*.*#" -x "*/node_modules/*")

    cd ${curdir}
    
    if [[ ! -f ${destzip} ]] || [[ ! -s ${destzip} ]]; then
        echo
        echo "missing or zero length zip file"
        echo
        CleanUp
        exit 1
    fi
    [[ $verbosity -gt 1 ]] && unzip -l "${destzip}"
    
    apiproxyzip="${destzip}"
}


import_proxy_bundle() {
    local bundleZip="${apiproxyzip}"
    [[ $verbosity -gt 0 ]] && echo "Importing the bundle as ${proxyname}..."

    MYCURL -X POST -H "Content-Type: application/octet-stream" \
           "${mgmtserver}/v1/o/${orgname}/apis?action=import&name=${proxyname}" \
           -T ${bundleZip} 

    if [[ ${CURL_RC} -ne 201 ]]; then
        echo
        echoerror "failed importing the proxy ${proxyname}"
        cat ${CURL_OUT}
        echo
        echo
        importedRevision=""
    else
        [[ $verbosity -gt 1 ]] && cat ${CURL_OUT} && echo && echo

        ## what revision did we just import?
        importedRevision=$(cat ${CURL_OUT} | grep \"revision\" | tr '\r\n' ' ' | sed -E 's/"revision"|[:, "]//g')
        [[ $verbosity -gt 0 ]] && echo "This is revision $importedRevision"
    fi
    rm ${bundleZip}
 }


deploy_proxy() {
    local proxy="${proxyname}" rev=$importedRevision
    # org and environment do not vary
    [[ $verbosity -gt 0 ]] && echo "deploying revision ${rev} of proxy ${proxy}..."
    MYCURL -X POST -H "Content-type:application/x-www-form-urlencoded" \
           "${mgmtserver}/v1/o/${orgname}/e/${envname}/apis/${proxy}/revisions/${rev}/deployments" \
           -d 'override=true&delay=60'

    if [[ ${CURL_RC} -ne 200 ]]; then
        echo
        echoerror "failed deploying the revision."
        cat ${CURL_OUT}
        echo
        echo
        CleanUp
        exit 1
    fi  
}


create_rsa_key_pair() {
    local TIMESTAMP=$(date '+%Y%m%d-%H%M%S')
    local privateKeyFile=private-${TIMESTAMP}.pem
    privateKeyPkcs8File=private-pkcs8-${TIMESTAMP}.pem
    publicKeyFile=public-${TIMESTAMP}.pem
    openssl genrsa -out ${privateKeyFile} 2048
    openssl pkcs8 -topk8 -inform pem -in ${privateKeyFile} -outform pem -nocrypt -out ${privateKeyPkcs8File}
    openssl rsa -in ${privateKeyFile} -outform PEM -pubout -out ${publicKeyFile}
    [[ $verbosity -gt 0 ]] && echo "created keypair ${privateKeyPkcs8File} and ${publicKeyFile}"
}


verify_or_create_rsa_key_pair() {
    local privateKeyFiles numFiles onefile timestamp

    ## nullglob: fill empty array on globbing if no matches
    shopt -s nullglob
    
    # private-pkcs8-20161214-201107.pem
    privateKeyFiles=(private-pkcs8-*.pem)
    numFiles=${#privateKeyFiles[@]}
    if [[ $numFiles = 1 ]]; then
        onefile=${privateKeyFiles[0]}
        timestamp=${onefile:14:15}
        if [[ -f public-${timestamp}.pem ]]; then
            privateKeyPkcs8File=private-pkcs8-${timestamp}.pem
            publicKeyFile=public-${timestamp}.pem
            [[ $verbosity -gt 0 ]] && echo "found existing keypair ${privateKeyPkcs8File} and ${publicKeyFile}"
        else
            create_rsa_key_pair
        fi
    else
        [[ $verbosity -gt 0 ]] && echo "found multiple existing private key files..."
        create_rsa_key_pair
    fi
}


verify_or_create_api_product() {
    [[ $verbosity -gt 0 ]] && echo "check for the api product (${apiproductname})"
    MYCURL -X GET ${mgmtserver}/v1/o/${orgname}/apiproducts/${apiproductname}
    
    if [[ ${CURL_RC} -ne 200 ]]; then
        echo "create a new product (${apiproductname}) which contains the API proxy"
        MYCURL -X POST -H "Content-Type:application/json" \
          ${mgmtserver}/v1/o/${orgname}/apiproducts -d '{
           "approvalType" : "auto",
           "attributes" : [ ],
           "displayName" : "'${proxyname}' Test product '${apiproductname}'",
           "name" : "'${apiproductname}'",
           "apiResources" : [ "/**", "/" ],
           "description" : "Test for '${proxyname}'",
           "environments": [ "'${envname}'" ],
           "proxies": [ "'${proxyname}'" ]
          }'
        if [ ${CURL_RC} -ne 201 ]; then
            echo
            echo CURL_RC = ${CURL_RC}
            echoerror "  failed creating that product."
            cat ${CURL_OUT}
            echo
            echo
            CleanUp
            exit 1
        fi
    fi

    cat ${CURL_OUT}
    echo
    echo
}


verify_or_create_developer() {
    local shortdevname
    [[ $verbosity -gt 0 ]] && echo "checking the developer (${developerEmail})..."
    MYCURL -X GET ${mgmtserver}/v1/o/${orgname}/developers/${developerEmail}
    if [[ ${CURL_RC} -eq 200 ]]; then
        echo
        echo "OK. the developer exists."
    else
        shortdevname=${nametag}-`random_string`
        [[ $verbosity -gt 0 ]] && echo "create a new developer (${developerEmail})..."
        MYCURL -X POST -H "Content-type:application/json" \
               ${mgmtserver}/v1/o/${orgname}/developers \
               -d '{
    "email" : "'${developerEmail}'",
    "firstName" : "Dino",
    "lastName" : "Valentino",
    "userName" : "'${shortdevname}'",
    "organizationName" : "'${orgname}'",
    "status" : "active"
  }' 
        if [[ ${CURL_RC} -ne 201 ]]; then
            echo
            echo CURL_RC = ${CURL_RC}
            echoerror "  failed creating a new developer."
            cat ${CURL_OUT}
            echo
            echo
            CleanUp
            exit 1
        fi
    fi
}


verify_public_key() {
    local grepout 
    if [[ ! -f ${publicKeyFile} ]]; then
        echo "the file containing the public key (${publicKeyFile}) cannot be verified."
        echo 
        CleanUp
        exit 1
    fi
    # single square bracket to avoid pattern matching
    if [ ${publicKeyFile:(-4)} != ".pem" ]; then
        echo "you must use a pem-encoded cert file"
        CleanUp
        exit 1
    fi 
    grepout=$(grep -e "-----BEGIN PUBLIC KEY-----" ${publicKeyFile})
    if [[ $? -ne 0 ]]; then
        echo "cannot find the magic words in that file."
        CleanUp
        exit 1
    fi
    grepout=$(grep -e "-----END PUBLIC KEY-----" ${publicKeyFile})
    if [[ $? -ne 0 ]]; then
        echo "cannot find the magic words in that file."
        CleanUp
        exit 1
    fi
}



create_new_app() {
    local payload pubkey
    appname=${nametag}-`random_string`
    [[ $verbosity -gt 0 ]] && echo "create a new app (${appname}) for that developer, with authorization for the product..."

    payload=$'{\n'
    payload+=$'  "attributes" : [ {\n'
    payload+=$'     "name" : "creator",\n'
    payload+=$'     "value" : "provisioning script '
    payload+="$0"
    payload+=$'"\n'
    payload+=$'    },{\n'
    payload+=$'     "name" : "public_key",\n'
    payload+=$'     "value" : "'
    ## read in 
    pubkey=$(<"$publicKeyFile")
    # remove newlines
    pubkey=$(echo $pubkey | tr -d '\n')
    payload+="$pubkey"
    payload+=$'"\n'
    payload+=$'    } ],\n'
    payload+=$'  "apiProducts": [ "'
    payload+="${apiproductname}"
    payload+=$'" ],\n'
    payload+=$'    "callbackUrl" : "thisisnotused://www.apigee.com",\n'
    payload+=$'    "name" : "'
    payload+="${appname}"
    payload+=$'",\n'
    payload+=$'    "keyExpiresIn" : "'${eightDaysInMillseconds}$'"\n'
    payload+=$'}' 

    MYCURL -X POST \
           -H "Content-type:application/json" \
           ${mgmtserver}/v1/o/${orgname}/developers/${developerEmail}/apps \
           -d "${payload}"

    if [[ ${CURL_RC} -ne 201 ]]; then
        echo
        echo CURL_RC = ${CURL_RC}
        echoerror "  failed creating a new app."
        cat ${CURL_OUT}
        echo
        echo
        CleanUp
        exit 1
    fi
}


retrieve_app_keys() {
  local array
  [[ $verbosity -gt 0 ]] && echo "get the keys for that app..."
  MYCURL -X GET ${mgmtserver}/v1/o/${orgname}/developers/${developerEmail}/apps/${appname} 

  if [[ ${CURL_RC} -ne 200 ]]; then
      echo
      echo CURL_RC = ${CURL_RC}
    echoerror "  failed retrieving the app details."
    cat ${CURL_OUT}
    echo
    echo
    CleanUp
    exit 1
  fi  

  array=(`cat ${CURL_OUT} | grep "consumerKey" | sed -E 's/[",:]//g'`)
  consumerkey=${array[1]}
  array=(`cat ${CURL_OUT} | grep "consumerSecret" | sed -E 's/[",:]//g'`)
  consumersecret=${array[1]}
}


final_report() {
    echo 
    echo
    echo
    echo
    echo "private key file: ${privateKeyPkcs8File}"
    echo "public key file: ${publicKeyFile}"
    echo    
    echo "consumer key: ${consumerkey}"
    echo "consumer secret: ${consumersecret}"
    echo 
}


parse_deployments_output() {
    local output_parsed
    ## extract the environment names and revision numbers in the list of deployments.
    output_parsed=$(cat ${CURL_OUT} | grep -A 6 -B 2 "revision")

    if [ $? -eq 0 ]; then

        deployed_envs=`echo "${output_parsed}" | grep -B 2 revision | grep name | sed -E 's/[\",]//g'| sed -E 's/name ://g'`

        deployed_revs=`echo "${output_parsed}" | grep -A 5 revision | grep name | sed -E 's/[\",]//g'| sed -E 's/name ://g'`

        IFS=' '; declare -a rev_array=(${deployed_revs})
        IFS=' '; declare -a env_array=(${deployed_envs})

        m=${#rev_array[@]}
        [[ $verbosity -gt 0 ]] && echo "found ${m} deployed revisions"

        deployments=()
        let m-=1
        while [ $m -ge 0 ]; do
            rev=${rev_array[m]}
            env=${env_array[m]}
            # trim spaces
            rev="$(echo "${rev}" | tr -d '[[:space:]]')"
            env="$(echo "${env}" | tr -d '[[:space:]]')"
            echo "${env}=${rev}"
            deployments+=("${env}=${rev}")
            let m-=1
        done
        have_deployments=1
    fi
}

clear_env_state() {
    local prodarray devarray apparray revisionarray prod env rev deployment dev app i j

    echo "check for developers like ${nametag}..."
    MYCURL -X GET ${mgmtserver}/v1/o/${orgname}/developers
    if [[ ${CURL_RC} -ne 200 ]]; then
        echo 
        echoerror "Cannot retrieve developers from that org..."
        exit 1
    fi
    devarray=(`cat ${CURL_OUT} | grep "\[" | sed -E 's/[]",[]//g'`)
    
    [[ $verbosity -gt 2 ]] && echo "all developers: ${devarray[@]}"

    for i in "${!devarray[@]}"; do
        dev=${devarray[i]}
        if [[ "$dev" =~ ^${nametag}.+$ ]] ; then
            [[ $verbosity -gt 0 ]] && echo "found a matching developer..."
            [[ $verbosity -gt 0 ]] && echo "list the apps for that developer..."
            MYCURL -X GET "${mgmtserver}/v1/o/${orgname}/developers/${dev}/apps"
            apparray=(`cat ${CURL_OUT} | grep "\[" | sed -E 's/[]",[]//g'`)
            for j in "${!apparray[@]}"; do
                app=${apparray[j]}
                echo "delete the app ${app}..."
                MYCURL -X DELETE "${mgmtserver}/v1/o/${orgname}/developers/${dev}/apps/${app}"
                ## ignore errors
            done       

            echo "delete the developer $dev..."
            MYCURL -X DELETE "${mgmtserver}/v1/o/${orgname}/developers/${dev}"
            if [ ${CURL_RC} -ne 200 ]; then
                echo 
                echoerror "  could not delete that developer (${dev})"
                echo
                CleanUp
                exit 1
            fi
        fi
    done

    [[ $verbosity -gt 0 ]] && echo "check for api products like ${nametag}..."
    MYCURL -X GET ${mgmtserver}/v1/o/${orgname}/apiproducts
    if [[ ${CURL_RC} -ne 200 ]]; then
        echo 
        echoerror "Cannot retrieve apiproducts from that org..."
        echo
        CleanUp
        exit 1
    fi

    prodarray=(`cat ${CURL_OUT} | grep "\[" | sed -E 's/[]",[]//g'`)
    [[ $verbosity -gt 2 ]] && echo ${prodarray[@]}
    for i in "${!prodarray[@]}"; do
        prod=$(echo "${prodarray[i]}" | tr '[:upper:]' '[:lower:]')
        if [[ "$prod" =~ ^${nametag}.+$ ]] ; then
            echo "found a matching product...deleting it."
            MYCURL -X DELETE "${mgmtserver}/v1/o/${orgname}/apiproducts/${prodarray[i]}"
            if [ ${CURL_RC} -ne 200 ]; then
                echo
                echoerror "could not delete that product (${prod})"
                echo
                echo CURL_RC = ${CURL_RC}
                echo
                cat ${CURL_OUT}
                echo
                CleanUp
                exit 1
            fi
        fi
    done

    echo "check for the ${proxyname} apiproxy..."
    MYCURL -X GET "${mgmtserver}/v1/o/${orgname}/apis/${proxyname}"
    if [[ ${CURL_RC} -eq 200 ]]; then
        
        echo "checking deployments"
        MYCURL -X GET "${mgmtserver}/v1/o/${orgname}/apis/${proxyname}/deployments"
        if [[ ${CURL_RC} -eq 200 ]]; then
            echo "found, querying it..."
            parse_deployments_output

            # undeploy from any environments in which the proxy is deployed
            for deployment in ${deployments[@]}; do
                env=`expr "${deployment}" : '\([^=]*\)'`
                # trim spaces
                env="$(echo "${env}" | tr -d '[[:space:]]')"
                rev=`expr "$deployment" : '[^=]*=\([^=]*\)'`
                MYCURL -X POST "${mgmtserver}/v1/o/${orgname}/apis/${proxyname}/revisions/${rev}/deployments?action=undeploy&env=${env}"
                ## ignore errors
            done
        fi
        
        # delete all revisions
        MYCURL -X GET ${mgmtserver}/v1/o/${orgname}/apis/${proxyname}/revisions
        revisionarray=(`cat ${CURL_OUT} | grep "\[" | sed -E 's/[]",[]//g'`)
        for i in "${!revisionarray[@]}"; do
            rev=${revisionarray[i]}
            echo "delete revision $rev"
            MYCURL -X DELETE "${mgmtserver}/v1/o/${orgname}/apis/${proxyname}/revisions/${rev}"
            if [[ $CURL_RC -ne 200 ]]; then 
                echo
                echo CURL_RC = ${CURL_RC}
                echo
                cat ${CURL_OUT}
                echo
            fi
        done

        [[ $verbosity -gt 0 ]] && echo "delete the api"
        MYCURL -X DELETE ${mgmtserver}/v1/o/${orgname}/apis/${proxyname}
        if [[ ${CURL_RC} -ne 200 ]]; then
            echo "failed to delete that API"
            echo
            echo CURL_RC = ${CURL_RC}
            echo
            cat ${CURL_OUT}
            echo
        fi 
    fi

    [[ $verbosity -gt 0 ]] && echo "checking for the cache ${requiredcache}"
    MYCURL -X GET ${mgmtserver}/v1/o/${orgname}/e/${envname}/caches/${requiredcache}
    if [[ ${CURL_RC} -eq 200 ]]; then
        MYCURL -X DELETE ${mgmtserver}/v1/o/${orgname}/e/${envname}/caches/${requiredcache}
        if [[ ${CURL_RC} -ne 200 ]]; then
            echo "failed to delete the cache"
            echo
            echo CURL_RC = ${CURL_RC}
            echo
            cat ${CURL_OUT}
            echo
        fi 
    fi

}



## =======================================================

while getopts "hm:o:e:u:nd:p:qvrS" opt; do
  case $opt in
    h) usage ;;
    m) mgmtserver=$OPTARG ;;
    o) orgname=$OPTARG ;;
    e) envname=$OPTARG ;;
    u) credentials="-u $OPTARG" ;;
    n) netrccreds=1 ;;
    p) apiproductname=$OPTARG ;;
    d) developerEmail=$OPTARG ;;
    r) resetAll=1 ;;
    S) want_deploy=0 ;;
    q) verbosity=$(($verbosity-1)) ;;
    v) verbosity=$(($verbosity+1)) ;;
    *) echo "unknown arg" && usage ;;
  esac
done

echo
if [[ "X$mgmtserver" = "X" ]]; then
  mgmtserver="$defaultmgmtserver"
fi 

if [[ "X$orgname" = "X" ]]; then
    echo "You must specify an org name (-o)."
    echo
    usage
    exit 1
fi

if [[ "X$credentials" = "X" ]]; then
  if [[ ${netrccreds} -eq 1 ]]; then
    credentials='-n'
  else
    choose_credentials
  fi 
else
  maybe_ask_password
fi 


if [[ $resetAll -eq 0 ]]; then
    if [[ "X$developerEmail" = "X" ]]; then
        echo "You must specify a developer email (-d)."
        echo
        usage
        exit 1
    fi
fi

check_org 
if [[ ${check_org} -ne 0 ]]; then
  echo "that org cannot be validated"
  CleanUp
  exit 1
fi

if [[ $resetAll -eq 1 ]]; then 
    clear_env_state
else 
    verify_or_create_rsa_key_pair

    verify_or_create_cache

    if [[ $want_deploy -eq 1 ]]; then
        produce_proxy_zip

        [[ ! -f "${apiproxyzip}" ]] && echo "no API proxy zip" && exit 1

        import_proxy_bundle

        [[ ! -n "$importedRevision" ]] && echo "the import failed" && exit 1

        deploy_proxy
    fi

    verify_or_create_api_product
    verify_or_create_developer
    
    verify_public_key
    create_new_app
    retrieve_app_keys

    final_report
fi

CleanUp
exit 0

