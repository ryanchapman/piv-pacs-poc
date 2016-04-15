#!/bin/bash -
#
# ECC CA build script
# Based on NIST Test PIV CA/cards
# http://csrc.nist.gov/groups/SNS/piv/documents/test-piv-card-data-specifications.pdf
#
# Ryan A. Chapman, ryan@rchapman.org
# Sat Jan 23 02:37:14 MST 2016

OPENSSL=/usr/local/Cellar/openssl/1.0.2g/bin/openssl
YUBICO_PIV_TOOL=~/bin/yubico-piv-tool
#
#  Set the passwords
#
PASSWORD_CA=$(grep output_password trustanchor-ca.cnf | sed 's/.*=//;s/^ *//')
PASSWORD_ECC_P256_CA=$(grep output_password eccp256issuing-ca.cnf | sed 's/.*=//;s/^ *//')

CA_DEFAULT_DAYS=$(grep default_days trustanchor-ca.cnf | sed 's/.*=//;s/^ *//')
CA_DEFAULT_DAYS_ECC_P256_CA=$(grep default_days eccp256issuing-ca.cnf | tail -n1 | sed 's/.*=//;s/^ *//')
CRL_DEFAULT_DAYS=$(grep default_crl_days trustanchor-ca.cnf | sed 's/.*=//;s/^ *//')
CRL_DEFAULT_DAYS_ECC_P256_CA=$(grep default_crl_days eccp256issuing-ca.cnf | sed 's/.*=//;s/^ *//')

TRUE=0
FALSE=1

if [[ "$1" =~ "^-h" ]]; then
    echo "usage: not meant to be called directly.  See makefile for targets."
    exit 1
fi

which uuidgen &>/dev/null || {
    logit "Error: uuidgen program not installed."
}

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

function run_ignerr
{
    _run warn $*
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

function cleanall ()
{
    run rm -f trustanchor-ca.csr trustanchor-ca.key trustanchor-ca.crt trustanchor-ca.der \
        trustanchor-ca.pem trustanchor-ca.der trustanchor-ca-index.txt \
        trustanchor-ca-serial trustanchor-ca-index.txt.attr TrustAnchor.crl \
        eccp256issuing-ca.csr eccp256issuing-ca.key eccp256caissuing-ca.crt eccp256issuing-ca.der \
        eccp256issuing-ca.pem eccp256issuing-ca.der eccp256issuing-ca-index.txt \
        eccp256issuing-ca-serial eccp256issuing-ca-index.txt.attr \
        eccp256pivcontentsigner.pem eccp256pivcontentsigner.key eccp256pivcontentsigner.der \
        client-piv-auth-cert-slot-9a.csr client-piv-auth-cert-slot-9a.key client-piv-auth-cert-slot-9a.crt \
        client-piv-auth-cert-slot-9a.pem client-piv-auth-cert-slot-9a.der \
        client-digital-signature-slot-9c.csr client-digital-signature-slot-9c.key client-digital-signature-slot-9c.crt \
        client-digital-signature-slot-9c.pem client-digital-signature-slot-9c.der \
        client-key-management-slot-9d.csr client-key-management-slot-9d.key client-key-management-slot-9d.crt \
        client-key-management-slot-9d.pem client-key-management-slot-9d.der \
        client-card-auth-slot-9e.csr client-card-auth-slot-9e.key client-card-auth-slot-9e.crt \
        client-card-auth-slot-9e.pem client-card-auth-slot-9e.der \
        client-chuid.hex CAdir/* \
        *.old CACertsIssued*.p7c *.pem *.crl *~ dh random *\.0 *\.1 *.der *.p12 *.csr *.p7b
    exit 0
}

# Create the certificate authorities
function ca ()
{
    local need_upload=$FALSE  # do we need to scp anything?

    if [[ -f trustanchor-ca.key || -f trustanchor-ca.pem || -f eccp256issuing-ca.key || -f eccp256issuing-ca.pem ]]; then
        logit FATAL "Appears that CAs have been created. Run 'make cleanall' if you want to re-create them."
    fi

    if [[ ! -f trustanchor-ca-index.txt ]]; then
        touch trustanchor-ca-index.txt
    fi

    if [[ ! -f  trustanchor-ca-serial ]]; then
        echo '01' > trustanchor-ca-serial
    fi

    if [[ ! -f eccp256issuing-ca-index.txt ]]; then
        touch eccp256issuing-ca-index.txt
    fi

    if [[ ! -f eccp256issuing-ca-serial ]]; then
        echo '01' > eccp256issuing-ca-serial
    fi

    if [[ ! -f random ]]; then
        if [ -c /dev/urandom ]; then
            dd if=/dev/urandom of=./random count=10 >/dev/null 2>&1
        else
            date > ./random
        fi
    fi


    ###################################################################################
    #
    #  Create a new root self-signed CA certificate (NIST calls this trust anchor)
    #
    ###################################################################################

    # trustanchor (root CA) is RSA
    if [[ ! -f trustanchor-ca.key || ! -f trustanchor-ca.pem ]]; then
        if [[ ! -f trustanchor-ca.cnf ]]; then
            echo "Config file trustanchor-ca.cnf is missing. Cannot continue"
            exit 1
        fi

        logit "Building root CA: trustanchor-ca.{key,pem,der}"
        run $OPENSSL req -new -x509 -keyout trustanchor-ca.key -out trustanchor-ca.pem \
            -days $CA_DEFAULT_DAYS -set_serial 1 -sha256 -config ./trustanchor-ca-selfsign.cnf
        run $OPENSSL x509 -in trustanchor-ca.pem -out trustanchor-ca.der -outform DER
        logit "Building root CA: trustanchor-ca.{key,pem,der}: done"
    fi

    if [[ ! -f TrustAnchor.crl ]]; then
        logit "Building TrustAnchor.crl"
        run $OPENSSL ca -gencrl -crldays $CRL_DEFAULT_DAYS -out TrustAnchor.crl \
            -key $PASSWORD_CA -config ./trustanchor-ca-selfsign.cnf
        need_upload=$TRUE
        logit "Building TrustAnchor.crl: done"
    fi

    if [[ ! -f CACertsIssuedToTrustAnchor.p7c ]]; then
        # Since the Trust Anchor is a self signed cert, it has not been issued any CA certs itself, so
        # we can just pull the blank one from the NIST PIV Test card site
        logit "Building CACertsIssuedToTrustAnchor.p7c"
        curl -o CACertsIssuedToTrustAnchor.p7c http://smime2.nist.gov/PIVTest/CACertsIssuedToTrustAnchor.p7c
        need_upload=$TRUE
        logit "Building CACertsIssuedToTrustAnchor.p7c: done"
    fi

    # intermediate CA is ECC P256
    if [[ ! -f eccp256issuing-ca.key || ! -f eccp256issuing-ca.pem ]]; then
            if [[ ! -f eccp256issuing-ca.cnf ]]; then
            echo "Config file eccp256issuing-ca.cnf is missing. Cannot continue"
            exit 1
        fi

        logit "Building intermediate CA: eccp256issuing-ca.{key,pem,der}"
        run $OPENSSL ecparam -name prime256v1 -genkey -out eccp256issuing-ca.key
        run $OPENSSL req -new -key eccp256issuing-ca.key -out eccp256issuing-ca.csr \
            -days $CA_DEFAULT_DAYS_ECC_P256_CA -set_serial 1 -sha256 -config ./eccp256issuing-ca.cnf
        run $OPENSSL ca -batch -keyfile trustanchor-ca.key -cert trustanchor-ca.pem -in eccp256issuing-ca.csr -key $PASSWORD_CA \
            -out eccp256issuing-ca.pem -config ./trustanchor-ca.cnf
        # Verify the pubkey is the same in both the keyfile and the certificate.  Preventing a regression.
        run $OPENSSL ec -in eccp256issuing-ca.key -text | grep -A5 pub: | perl -pe 's/^\s+//g' >/tmp/eccp256-ca-pub-from-keyfile
        run $OPENSSL x509 -noout -text -in eccp256issuing-ca.pem | grep -A5 pub: | perl -pe 's/^\s+//g' >/tmp/eccp256-ca-pub-from-cert
        diff -aBwy --suppress-common-lines /tmp/eccp256-ca-pub-from-keyfile /tmp/eccp256-ca-pub-from-cert
        if [[ $? != 0 ]]; then
            cat <<-EOF
                ECCP256CA: pubkey mismatch in cert vs keyfile.
                pubkey in key file eccp256issuing-ca.key does not match the certificate file eccp256issuing-ca.pem
                this means the key file was not used to generate the cert. When you import the key onto your smart card
                you will find that challenges to the card (GENERAL_AUTHENTICATE [CLA 00 INS 87]) will fail
EOF
            exit 1
        fi
#        run $OPENSSL x509 -in eccp256issuing-ca.pem -out eccp256issuing-ca.der -outform DER
        logit "Building intermediate CA: eccp256issuing-ca.{key,pem,der}: done"
    fi

    if [[ ! -f ECCP-256CA.crl ]]; then
        logit "Building ECCP-256CA.crl"
        run $OPENSSL ca -gencrl -crldays $CRL_DEFAULT_DAYS_ECC_P256_CA -out ECCP-256CA.crl \
            -key $PASSWORD_ECC_P256_CA -config ./eccp256issuing-ca.cnf
        need_upload=$TRUE
        logit "Building ECCP-256CA.crl: done"
    fi

    if [[ ! -f CACertsIssuedByTrustAnchor.p7c ]]; then
        logit "Building CACertsIssuedByTrustAnchor.p7c"
        # Trust Anchor has only issued the ECCP-256 CA cert, so convert that cert to PKCS7
        run $OPENSSL crl2pkcs7 -nocrl -certfile eccp256issuing-ca.pem -out CACertsIssuedByTrustAnchor.p7c \
            -outform DER
        need_upload=$TRUE
        logit "Building CACertsIssuedByTrustAnchor.p7c: done"
    fi

    if [[ ! -f CACertsIssuedToECCP-256CA.p7c ]]; then
        logit "Building CACertsIssuedToECCP-256CA.p7c"
        run $OPENSSL crl2pkcs7 -nocrl -certfile eccp256issuing-ca.pem -out CACertsIssuedToECCP-256CA.p7c \
            -outform DER
        need_upload=$TRUE
        logit "Building CACertsIssuedToECCP-256CA.p7c: done"
    fi

    if [[ ! -f CACertsIssuedByECCP-256CA.p7c ]]; then
        logit "Building CACertsIssuedByECCP-256CA.p7c"
        # This file has no certs in it on the NIST PIV Test card site, so just copy it from them
        # we can just pull the blank one from the NIST PIV Test card site
        run curl -o CACertsIssuedByECCP-256CA.p7c http://smime2.nist.gov/PIVTest/CACertsIssuedByECCP-256CA.p7c
        need_upload=$TRUE
        logit "Building CACertsIssuedByECCP-256CA.p7c: done"
    fi

    if [[ ! -f eccp256pivcontentsigner.key || ! -f eccp256pivcontentsigner.pem ]]; then
        if [[ ! -f eccp256pivcontentsigner.cnf ]]; then
            echo "Config file eccp256pivcontentsigner.cnf is missing. Cannot continue"
            exit 1
        fi

        logit "Building piv content signer cert: eccp256pivcontentsigner.{key,pem,der}"
        run $OPENSSL ecparam -name prime256v1 -genkey -out eccp256pivcontentsigner.key
        run $OPENSSL req -new -key eccp256pivcontentsigner.key -out eccp256pivcontentsigner.csr -sha256 -config ./eccp256pivcontentsigner.cnf

        run $OPENSSL ca -batch -keyfile eccp256issuing-ca.key -cert eccp256issuing-ca.pem -in eccp256pivcontentsigner.csr -key $PASSWORD_ECC_P256_CA \
            -out eccp256pivcontentsigner.pem -config ./eccp256pivcontentsigner.cnf

        # Verify the pubkey is the same in both the keyfile and the certificate.  Preventing a regression.
        run $OPENSSL ec -in eccp256pivcontentsigner.key -text | grep -A5 pub: | perl -pe 's/^\s+//g' >/tmp/piv-content-signer-pub-from-keyfile
        run $OPENSSL x509 -noout -text -in eccp256pivcontentsigner.pem | grep -A5 pub: | perl -pe 's/^\s+//g' >/tmp/piv-content-signer-pub-from-cert
        diff -aBwy --suppress-common-lines /tmp/piv-content-signer-pub-from-keyfile /tmp/piv-content-signer-pub-from-cert
        if [[ $? != 0 ]]; then
            cat <<-EOF
                PIV Content Signer cert: pubkey mismatch in cert vs keyfile.
                pubkey in key file eccp256pivcontentsigner.key does not match the certificate file eccp256pivcontentsigner.pem
                this means the key file was not used to generate the cert.
EOF
            exit 1
        fi
#        run $OPENSSL x509 -in eccp256pivcontentsigner.pem -out eccp256pivcontentsigner.der -outform DER
        logit "Building piv content signer cert: eccp256pivcontentsigner.{key,pem,der}: done"
    fi

    # Convert ECC P-256 CA to PKCS12 and import into Java Keystore so that CHUID's can be signed
    # password 'whatever' is hard coded into YubikeyCHUID signing program.
    # TOOD: change hardcoded password
    logit "Generating Java Keystore for use by YubikeyCHUID program"
    if [[ -f keysupport-java-api/src/mykeystore.jks ]]; then
        rm -f keysupport-java-api/src/mykeystore.jks
    fi

    [[ -f eccp256pivcontentsigner-bundle.pem ]] && run rm -f eccp256pivcontentsigner-bundle.pem

    cat trustanchor-ca.pem eccp256issuing-ca.pem > ca-bundle.pem
    run $OPENSSL pkcs12 -export -chain -name myservercert \
        -CAfile ca-bundle.pem \
        -in eccp256pivcontentsigner.pem -inkey eccp256pivcontentsigner.key \
        -out eccp256pivcontentsigner.p12 -passout pass:whatever
    run keytool -importkeystore -destkeystore keysupport-java-api/src/mykeystore.jks \
        -srckeystore eccp256pivcontentsigner.p12 -srcstoretype pkcs12 \
        -alias myservercert -deststorepass whatever -srcstorepass whatever
    logit "Generating Java Keystore for use by YubikeyCHUID program: done"

    # upload issuedto and issuedby cert info and CRLs to internet server
    #if [[ $need_upload == $TRUE ]]; then
    #    logit "Uploading certs to certs.myorg.com and CRLs to crl.myorg.com via scp"
    #    run scp CACertsIssuedByTrustAnchor.p7c \
    #        CACertsIssuedToTrustAnchor.p7c \
    #        CACertsIssuedToECCP-256CA.p7c \
    #         pacs-ca:/var/www/certs.myorg.com/
    #    run scp TrustAnchor.crl \
    #        ECCP-256CA.crl \
    #         pacs-ca:/var/www/crl.myorg.com/
    #    logit "Uploading certs to certs.myorg.com and CRLs to crl.myorg.com via scp: done"
    #fi
}

function client ()
{
    # client certs
    if [[ ! -f client-piv-auth-cert-slot-9a.key || ! -f client-piv-auth-cert-slot-9a.pem ]]; then
        if [[ ! -f client-piv-auth-cert-slot-9a.cnf ]]; then
            echo "Config file client-piv-auth-cert-slot-9a.cnf is missing. Cannot continue"
            exit 1
        fi

        logit "Generating GUID"
        # TODO: change to non hard coded GUID once testing complete
        OPENSSL_PIV_GUID=d18b1e0d-3938-4601-9f5f-b9a6d0442e4d
        #OPENSSL_PIV_GUID=$(uuidgen | tr '[A-Z]' '[a-z]')
        export OPENSSL_PIV_GUID
        logit "GUID is '${OPENSSL_PIV_GUID}'"
        logit "Generating GUID: done"

        logit "Building 9A client cert: client-piv-auth-cert-slot-9a.key and client-piv-auth-cert-slot-9a.pem"
        run $OPENSSL ecparam -name prime256v1 -genkey -out client-piv-auth-cert-slot-9a.key
        run $OPENSSL req -new -key client-piv-auth-cert-slot-9a.key -out client-piv-auth-cert-slot-9a.csr -sha256 -config ./client-piv-auth-cert-slot-9a.cnf

        run $OPENSSL ca -batch -keyfile eccp256issuing-ca.key -cert eccp256issuing-ca.pem -in client-piv-auth-cert-slot-9a.csr -key $PASSWORD_ECC_P256_CA \
            -out client-piv-auth-cert-slot-9a.pem -config ./client-piv-auth-cert-slot-9a.cnf

        # Verify the pubkey is the same in both the keyfile and the certificate.  Preventing a regression.
        run $OPENSSL ec -in client-piv-auth-cert-slot-9a.key -text | grep -A5 pub: | perl -pe 's/^\s+//g' >/tmp/9a-pub-from-keyfile
        run $OPENSSL x509 -noout -text -in client-piv-auth-cert-slot-9a.pem | grep -A5 pub: | perl -pe 's/^\s+//g' >/tmp/9a-pub-from-cert
        # pubkey in key file client-piv-auth-cert-slot-9a.key does not match the certificate file client-piv-auth-cert-slot-9a.pem
        # this means the key file was not used to generate the cert. When you import the key onto your smart card
        # you will find that challenges to the card (GENERAL_AUTHENTICATE [CLA 00 INS 87]) will fail
        diff -aBwy --suppress-common-lines /tmp/9a-pub-from-keyfile /tmp/9a-pub-from-cert || echo "9A: pubkey mismatch in cert vs keyfile. see Makefile for more info"
        if [[ $? != 0 ]]; then
            cat <<-EOF
                Client 9A: pubkey mismatch in cert vs keyfile.
                pubkey in key file client-piv-auth-cert-slot-9a.key does not match the certificate file client-piv-auth-cert-slot-9a.pem
                this means the key file was not used to generate the cert. When you import the key onto your smart card
                you will find that challenges to the card (GENERAL_AUTHENTICATE [CLA 00 INS 87]) will fail
EOF
            exit 1
        fi
        logit "Building 9A client cert: client-piv-auth-cert-slot-9a.key and client-piv-auth-cert-slot-9a.pem: done"
    fi

    if [[ ! -f client-digital-signature-slot-9c.key || ! -f client-digital-signature-slot-9c.pem ]]; then
        if [[ ! -f client-digital-signature-slot-9c.cnf ]]; then
            echo "Config file client-digital-signature-slot-9c.cnf is missing. Cannot continue"
            exit 1
        fi

        logit "Building 9C client cert: client-digital-signature-slot-9c.key and client-digital-signature-slot-9c.pem"
        run $OPENSSL ecparam -name prime256v1 -genkey -out client-digital-signature-slot-9c.key
        run $OPENSSL req -new -key client-digital-signature-slot-9c.key -out client-digital-signature-slot-9c.csr -sha256 -config ./client-digital-signature-slot-9c.cnf

        run $OPENSSL ca -batch -keyfile eccp256issuing-ca.key -cert eccp256issuing-ca.pem -in client-digital-signature-slot-9c.csr -key $PASSWORD_ECC_P256_CA \
            -out client-digital-signature-slot-9c.pem -config ./client-digital-signature-slot-9c.cnf

        # Verify the pubkey is the same in both the keyfile and the certificate.  Preventing a regression.
        run $OPENSSL ec -in client-digital-signature-slot-9c.key -text | grep -A5 pub: | perl -pe 's/^\s+//g' >/tmp/9c-pub-from-keyfile
        run $OPENSSL x509 -noout -text -in client-digital-signature-slot-9c.pem | grep -A5 pub: | perl -pe 's/^\s+//g' >/tmp/9c-pub-from-cert
        # pubkey in key file client-digital-signature-slot-9c.key does not match the certificate file client-digital-signature-slot-9c.pem
        # this means the key file was not used to generate the cert. When you import the key onto your smart card
        # you will find that challenges to the card (GENERAL_AUTHENTICATE [CLA 00 INS 87]) will fail
        diff -aBwy --suppress-common-lines /tmp/9c-pub-from-keyfile /tmp/9c-pub-from-cert || echo "9C: pubkey mismatch in cert vs keyfile. see Makefile for more info"
        if [[ $? != 0 ]]; then
            cat <<-EOF
                Client 9C: pubkey mismatch in cert vs keyfile.
                pubkey in key file client-digital-signature-slot-9c.key does not match the certificate file client-digital-signature-slot-9c.pem
                this means the key file was not used to generate the cert. When you import the key onto your smart card
                you will find that challenges to the card (GENERAL_AUTHENTICATE [CLA 00 INS 87]) will fail
EOF
            exit 1
        fi
        logit "Building 9C client cert: client-digital-signature-9c.key and client-digital-signature-slot-9c.pem: done"
    fi

    if [[ ! -f client-key-management-slot-9d.key || ! -f client-key-management-slot-9d.pem ]]; then
        if [[ ! -f client-key-management-slot-9d.cnf ]]; then
            echo "Config file client-key-management-slot-9d.cnf is missing. Cannot continue"
            exit 1
        fi

        logit "Building 9D client cert: client-key-management-slot-9d.key and client-key-management-slot-9d.pem"
        run $OPENSSL ecparam -name prime256v1 -genkey -out client-key-management-slot-9d.key
        run $OPENSSL req -new -key client-key-management-slot-9d.key -out client-key-management-slot-9d.csr -sha256 -config ./client-key-management-slot-9d.cnf

        run $OPENSSL ca -batch -keyfile eccp256issuing-ca.key -cert eccp256issuing-ca.pem -in client-key-management-slot-9d.csr -key $PASSWORD_ECC_P256_CA \
            -out client-key-management-slot-9d.pem -config ./client-key-management-slot-9d.cnf

        # Verify the pubkey is the same in both the keyfile and the certificate.  Preventing a regression.
        run $OPENSSL ec -in client-key-management-slot-9d.key -text | grep -A5 pub: | perl -pe 's/^\s+//g' >/tmp/9d-pub-from-keyfile
        run $OPENSSL x509 -noout -text -in client-key-management-slot-9d.pem | grep -A5 pub: | perl -pe 's/^\s+//g' >/tmp/9d-pub-from-cert
        diff -aBwy --suppress-common-lines /tmp/9d-pub-from-keyfile /tmp/9d-pub-from-cert
        if [[ $? != 0 ]]; then
            cat <<-EOF
                Client 9D: pubkey mismatch in cert vs keyfile.
                pubkey in key file client-key-management-slot-9d.key does not match the certificate file client-key-management-slot-9d.pem
                this means the key file was not used to generate the cert. When you import the key onto your smart card
                you will find that challenges to the card (GENERAL_AUTHENTICATE [CLA 00 INS 87]) will fail
EOF
            exit 1
        fi
        logit "Building 9D client cert: client-key-management-slot-9d.key and client-key-management-slot-9d.pem: done"
    fi

    if [[ ! -f client-card-auth-slot-9e.key || ! -f client-card-auth-slot-9e.pem ]]; then
       if [[ ! -f client-card-auth-slot-9e.cnf ]]; then
            echo "Config file client-card-auth-slot-9e.cnf is missing. Cannot continue"
            exit 1
        fi

        logit "Building 9E client cert: client-card-auth-slot-9e.key and client-card-auth-slot-9e.pem"
        run $OPENSSL ecparam -name prime256v1 -genkey -out client-card-auth-slot-9e.key
        run $OPENSSL req -new -key client-card-auth-slot-9e.key -out client-card-auth-slot-9e.csr -sha256 -config ./client-card-auth-slot-9e.cnf

        run $OPENSSL ca -batch -keyfile eccp256issuing-ca.key -cert eccp256issuing-ca.pem -in client-card-auth-slot-9e.csr -key $PASSWORD_ECC_P256_CA \
            -out client-card-auth-slot-9e.pem -config ./client-card-auth-slot-9e.cnf

        # Verify the pubkey is the same in both the keyfile and the certificate.  Preventing a regression.
        $OPENSSL ec -in client-card-auth-slot-9e.key -text | grep -A5 pub: | perl -pe 's/^\s+//g' >/tmp/9e-pub-from-keyfile
        $OPENSSL x509 -noout -text -in client-card-auth-slot-9e.pem | grep -A5 pub: | perl -pe 's/^\s+//g' >/tmp/9e-pub-from-cert
        diff -aBwy --suppress-common-lines /tmp/9e-pub-from-keyfile /tmp/9e-pub-from-cert
        if [[ $? != 0 ]]; then
            cat <<-EOF
                Client 9E: pubkey mismatch in cert vs keyfile.
                pubkey in key file client-card-auth-slot-9e.key does not match the certificate file client-card-auth-slot-9e.pem
                this means the key file was not used to generate the cert. When you import the key onto your smart card
                you will find that challenges to the card (GENERAL_AUTHENTICATE [CLA 00 INS 87]) will fail
EOF
            exit 1
        fi
        logit "Building 9E client cert: client-card-auth-slot-9e.key and client-card-auth-slot-9e.pem: done"
    fi

    if [[ ! -f client-chuid.hex ]]; then
        logit "Building CHUID"
        (cd keysupport-java-api/src/ && javac org/keysupport/tests/CHUIDTest.java && \
            run java org/keysupport/tests/YubikeyCHUID ${OPENSSL_PIV_GUID} ../../client-chuid.hex)
        logit "Building CHUID: done"
    fi
}

function yubikey () {
    # if there is a yubikey plugged in, write certs to it
    $YUBICO_PIV_TOOL -a status &>/dev/null
    if [[ $? == $TRUE ]]; then
        printf "Do you want to write certs and keys to the Yubikey? (y/n):  "
        read ANS
        if [[ "$ANS" == "y" || "$ANS" == "yes" ]]; then
            logit "Writing CCC"
            $YUBICO_PIV_TOOL -a set-ccc
            logit "Writing CCC: done"
            logit "Writing CHUID"
            $YUBICO_PIV_TOOL -a write-object --id 0x5fc102 -i client-chuid.hex
            logit "Writing CHUID: done"
            logit "Writing cert to slot 9A"
            $YUBICO_PIV_TOOL -a import-certificate -s 9a -i client-piv-auth-cert-slot-9a.pem
            logit "Writing cert to slot 9A: done"
            logit "Writing key  to slot 9A"
            $YUBICO_PIV_TOOL -a import-key -s 9a -i client-piv-auth-cert-slot-9a.key
            logit "Writing key  to slot 9A: done"
            #
            logit "Writing cert to slot 9C"
            $YUBICO_PIV_TOOL -a import-certificate -s 9c -i client-digital-signature-slot-9c.pem
            logit "Writing cert to slot 9C: done"
            logit "Writing key  to slot 9C"
            $YUBICO_PIV_TOOL -a import-key -s 9c -i client-digital-signature-slot-9c.key
            logit "Writing key  to slot 9C: done"
            #
            logit "Writing cert to slot 9D"
            $YUBICO_PIV_TOOL -a import-certificate -s 9d -i client-key-management-slot-9d.pem
            logit "Writing cert to slot 9D: done"
            logit "Writing key  to slot 9D"
            $YUBICO_PIV_TOOL -a import-key -s 9d -i client-key-management-slot-9d.key
            logit "Writing key  to slot 9D: done"
            #
            logit "Writing cert to slot 9E"
            $YUBICO_PIV_TOOL -a import-certificate -s 9e -i client-card-auth-slot-9e.pem
            logit "Writing cert to slot 9E: done"
            logit "Writing key  to slot 9E"
            $YUBICO_PIV_TOOL -a import-key -s 9e -i client-card-auth-slot-9e.key
            logit "Writing key  to slot 9E: done"
            logit "Status of Yubikey:"
            $YUBICO_PIV_TOOL -a status
        fi
    fi

}


#################################
# main
#################################

function main () {
    func_to_exec=${1}
    type ${func_to_exec} 2>&1 | grep -q 'function' >&/dev/null || {
        logit "$(basename $0): ERROR: function '${func_to_exec}' not found."
        exit 1
    }

    shift
    ${func_to_exec} $*
    echo
}

# did someone source this file or execute it directly?  If not sourced, then we are responsible for
# executing main().  Files sourcing this one are responsible for calling main()
sourced=$FALSE
[ "$0" = "$BASH_SOURCE" ] || sourced=$TRUE

if [[ $sourced == $FALSE ]]; then
    main $*
fi
