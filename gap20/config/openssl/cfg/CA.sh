#!/bin/sh
#
# CA - wrapper around ca to make it easier to use ... basically ca requires
#      some setup stuff to be done before you can use it and this makes
#      things easier between now and when Eric is convinced to fix it :-)
#
# CA -newca ... will setup the right stuff
# CA -newreq ... will generate a certificate request
# CA -sign ... will sign the generated request and output
#

set -x #echo on

cp_pem() {
    infile=$1
    outfile=$2
    bound=$3
    flag=0
    exec <$infile;
    while read line; do
	if [ $flag -eq 1 ]; then
		echo $line|grep "^-----END.*$bound"  2>/dev/null 1>/dev/null
		if [ $? -eq 0 ] ; then
			echo $line >>$outfile
			break
		else
			echo $line >>$outfile
		fi
	fi

	echo $line|grep "^-----BEGIN.*$bound"  2>/dev/null 1>/dev/null
	if [ $? -eq 0 ]; then
		echo $line >$outfile
		flag=1
	fi
    done
}

usage() {
 echo "usage: $0 [options] <dev name> [config file]" >&2
 echo "options:"
 echo "    -h print this info."
 echo "    -c create CA"
 echo "    -r create cert and private key"
 echo "    -s signature certs by CA"
 echo "    -p pkcs12 certs"
 echo ""
 echo "Example: 1. create CA: ./CA.sh -c ca" >&2
 echo "2. Create server cert req: ./CA.sh -r server" >&2
 echo "3. Sign server cert req: ./CA.sh -s server" >&2
}

if [ -z "$OPENSSL" ]; then OPENSSL=openssl; fi

if [ -z "$DAYS" ] ; then DAYS="-days 3650" ; fi	# 10 year

if [ "$2" = "" ]; then
    echo "lack dev name"
    usage
    exit 1
fi

DEVNAME=$2

SSLEAY_CONFIG="-batch -config $DEVNAME.cnf"

if [ "$3" != "" ]; then SSLEAY_CONFIG="-batch -config $3"; fi

CADAYS="-days 35600"	# 100 years 
REQ="$OPENSSL req $SSLEAY_CONFIG"
CA="$OPENSSL ca $SSLEAY_CONFIG"
VERIFY="$OPENSSL verify"
X509="$OPENSSL x509"
PKCS12="$OPENSSL pkcs12"
RSA="$OPENSSL rsa"
UPD_RND="head /dev/urandom  >/dev/null"
USE_RND_DEV="-rand /dev/urandom"
CERT_CHECK="openssl x509 -noout -text"
GENKEY="openssl genrsa $USE_RND_DEV"
KEYLEN=2048
CREATE_SERIAL=

CATOP=./demoCA 
CERTS_PATH=${CATOP}/certs
CRL_PATH=${CATOP}/crl
CERTSREQ_PATH=${CATOP}/newcerts
PRIVATE_PATH=${CATOP}/private

DEVDAYS="-days 7120"  #20 years
DEV_KEY=$PRIVATE_PATH/$DEVNAME.key
DEV_CERT_REQ=$CERTSREQ_PATH/$DEVNAME.csr
DEV_CERT=$CERTS_PATH/$DEVNAME.crt
DEV_PFX=$CERTS_PATH/$DEVNAME.pfx

CA_KEY=$PRIVATE_PATH/ca.key
CA_CERT_REQ=$CERTSREQ_PATH/ca.csr
CA_CERT=$CERTS_PATH/ca.crt

RET=0
NEWCA=""
OPERATORS=0

#CA_PRIVATE_KEY_PWD="1111111111111111"
#DEV_PRIVATE_KEY_PWD="2111111111111111"
#EXPORT_PWD="3111111111111111"
CA_PRIVATE_KEY_PWD="Acorn25876617154"
DEV_PRIVATE_KEY_PWD="Acorn16124653472"
EXPORT_PWD="Acorn20341394532"


pkcs12(){
    echo "Making PFX ..."
    head /dev/urandom  >/dev/null
    $GENKEY -des3 -passout pass:$DEV_PRIVATE_KEY_PWD -out $DEV_KEY $KEYLEN
    openssl rsa -in $DEV_KEY -passin pass:$DEV_PRIVATE_KEY_PWD -out $DEV_KEY
    $REQ -new $DEVDAYS -key $DEV_KEY -passin pass:$DEV_PRIVATE_KEY_PWD -out $DEV_CERT_REQ
    $X509 -req -in $DEV_CERT_REQ -signkey $DEV_KEY -passin pass:$DEV_PRIVATE_KEY_PWD -out $DEV_CERT
    $PKCS12 -export -password pass:$EXPORT_PWD -clcerts -in $DEV_CERT -inkey $DEV_KEY  -out $DEV_PFX
    RET=$?
}

#function signature
signature() {
	# create a certificate
    if [ ! -f $DEV_CERT_REQ ]; then
        echo "$DEV_CERT_REQ doesn't exist, please run with -newreq first."
        exit 1
    fi
    if [ ! -f ${CATOP}/serial ]; then
	CREATE_SERIAL="-create_serial"
    fi

    head /dev/urandom  >/dev/null
    $CA $CREATE_SERIAL  -in $DEV_CERT_REQ -cert $CA_CERT -keyfile $CA_KEY -policy policy_anything -out $DEV_CERT
    $CERT_CHECK -in $DEV_CERT
    RET=$?
    echo "Signed certificate is in $DEV_CERT"
}

newreq(){
	# create a certificate request
    if [ ! -f $DEV_KEY ]; then
        $GENKEY -out $DEV_KEY $KEYLEN
    fi
    $REQ -new -key $DEV_KEY -out $DEV_CERT_REQ  $DAYS
    RET=$?
    echo "Request is in $DEV_CERT_REQ, private key is in $DEV_KEY"
}

newca(){
	# if explicitly asked for or it doesn't exist then setup the directory
    # structure that Eric likes to manage things
    NEW="1"
    if [ "$NEW" -o ! -f ${CATOP}/serial ]; then
	# create the directory hierarchy
	mkdir -p ${CATOP}
	mkdir -p ${CERTS_PATH}
	mkdir -p ${CRL_PATH}
	mkdir -p ${CERTSREQ_PATH}
	mkdir -p ${PRIVATE_PATH}
	touch ${CATOP}/index.txt
    fi
    if [ ! -f $CA_KEY ]; then
	echo "CA certificate filename (or enter to create)"
	read FILE

	# ask user for existing CA certificate
	if [ "$FILE" ]; then
	    cp_pem $FILE $CA_KEY PRIVATE
	    cp_pem $FILE $CA_CERT CERTIFICATE
	    RET=$?
	    if [ ! -f "${CATOP}/serial" ]; then
		$X509 -in $CA_CERT -noout -next_serial \
		      -out ${CATOP}/serial
	    fi
	else
	    echo "Making CA certificate ..."
	    head /dev/urandom  >/dev/null
	    $GENKEY -des3  -passout pass:$CA_PRIVATE_KEY_PWD  -out $CA_KEY $KEYLEN
            $REQ -new -x509 $CADAYS -key $CA_KEY -passin pass:$CA_PRIVATE_KEY_PWD -out $CA_CERT
	    $CERT_CHECK -in $CA_CERT
	    RET=$?
	fi
	exit $RET
    else
	echo "$DEV_KEY exist!"
    fi
}

while getopts ':hcrsp' opt; do
	case $opt in
		h) usage 
			exit 0 ;;
		c) NEWCA="y" ;;
		r) NEWREQ="y" ;;
		s) SIGN="y" ;;
		p) PKCS="y" ;;
		\?) usage 
			exit 0
		;;
	esac
done


if [ "$NEWCA" = "y" ] ; then
	newca
fi

if [ "$NEWREQ" = "y" ]; then
	newreq
fi

if [ "$SIGN" = "y" ]; then
	signature
fi

if [ "$PKCS" = "y" ]; then
        pkcs12
fi

exit $RET
