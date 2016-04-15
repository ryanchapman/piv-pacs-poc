#!/bin/bash -

function logit
{
    if [[ "${1}" == "FATAL" ]]; then
        fatal="FATAL"
        shift
    fi
    echo -n "$(date '+%b %d %H:%M:%S.%N %Z') $(basename -- $0)[$$]: "
    if [[ "${fatal}" == "FATAL" ]]; then echo -n "${fatal} "; fi
    echo "$*"
    if [[ "${fatal}" == "FATAL" ]]; then exit 1; fi
}

function run
{
    _run fatal $*
}

function _run
{
    if [[ $1 == fatal ]]; then
        errors_fatal=$TRUE
    else
        errors_fatal=$FALSE
    fi
    shift
    logit "$*"
    eval "$*"
    rc=$?
    logit "$* returned $rc"
    # fail hard and fast
    if [[ $rc != 0 && $errors_fatal == $TRUE ]]; then
        pwd
        exit 1
    fi
    return $rc
}

OPENSSL=/usr/local/Cellar/openssl101/1.0.1q/bin/openssl
CHAL_FILE=/tmp/chal_file
CHAL_FILE_HASH=/tmp/chal_file_hash
CERT_9E=/tmp/9e
PUBKEY_PART=/tmp/nist/pubkey-part
SIG_FILE=/tmp/sigfile
SIG2_FILE=/tmp/sigfile2

run dd if=/dev/urandom of=$CHAL_FILE bs=32 count=1
echo "$OPENSSL sha -sha256 -binary < $CHAL_FILE > $CHAL_FILE_HASH"
$OPENSSL sha -sha256 -binary < $CHAL_FILE > $CHAL_FILE_HASH
run pkcs15-tool --no-cache --read-certificate 4 -o $CERT_9E

# sign challenge
run pkcs15-crypt -s -k 4 --sha-256 -i $CHAL_FILE_HASH -o $SIG2_FILE
echo "~/bin/ecdsa-pkcs11-to-asn1 < $SIG2_FILE > $SIG_FILE"
~/bin/ecdsa-pkcs11-to-asn1 < $SIG2_FILE > $SIG_FILE
echo "Verifying cert was signed by CA"
#run cat ${CERT_9E} | $OPENSSL verify -CApath ~/piv/ca/hid/CAdir/ -verbose
run "cat ${CERT_9E} | $OPENSSL verify -CApath /tmp/nist -verbose"
if [[ $? = 0 ]]; then
    logit "Verifying cert was signed by CA: verified OK."
else
    logit "Verifying cert was signed by CA: FAILED."
fi

run $OPENSSL x509 -pubkey -noout -in $CERT_9E > $PUBKEY_PART

logit "Verifying signature"
run $OPENSSL dgst -sha256 -verify $PUBKEY_PART -signature $SIG_FILE $CHAL_FILE
