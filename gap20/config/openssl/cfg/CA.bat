@echo on

if "%2" == "" goto usage

set WORK_DIR=%cd%
set DEVNAME=%2
set OPENSSL_CONF=%3
if "%3" == "" (
    set OPENSSL_CONF=%DEVNAME%.cnf
)
set SSLEAY_CONFIG=-batch -config %OPENSSL_CONF%

set OPENSSL=openssl.exe
:: 10 year
set DAYS=-days 3650	
:: 100 years
set CADAYS=-days 35600	 
set REQ=%OPENSSL% req  %SSLEAY_CONFIG%
set CA=%OPENSSL% ca %SSLEAY_CONFIG%
set VERIFY=%OPENSSL% verify
set X509=%OPENSSL% x509
set PKCS12=%OPENSSL% pkcs12
::set USE_RND_DEV=-rand \dev\urandom
set CERT_CHECK=%OPENSSL% x509 -noout -text
set GENKEY=%OPENSSL% genrsa %USE_RND_DEV%
set KEYLEN=2048
set CREATE_SERIAL=
set CATOP=.\demoCA
set CERTS_PATH=%CATOP%\certs
set CRL_PATH=%CATOP%\crl
set CERTSREQ_PATH=%CATOP%\newcerts
set PRIVATE_PATH=%CATOP%\private
set DEV_KEY=%PRIVATE_PATH%\%DEVNAME%.key
set DEV_CERT_REQ=%CERTSREQ_PATH%\%DEVNAME%.csr
set DEV_CERT=%CERTS_PATH%\%DEVNAME%.crt

set CA_KEY=%PRIVATE_PATH%\ca.key
set CA_CERT_REQ=%CERTSREQ_PATH%\ca.csr
set CA_CERT=%CERTS_PATH%\ca.crt

if "%1"=="-newca" goto newca
if "%1"=="-newreq" goto newreq
if "%1"=="-sign" goto sign
goto usage
:newca
    :: if explicitly asked for or it doesn't exist then setup the directory
    echo %CATOP%\serial
    if not exist %CATOP%\serial (
	      :: create the directory hierarchy
	      mkdir %CATOP%
	  		mkdir %CERTS_PATH%
	      mkdir %CRL_PATH%
	      mkdir %CERTSREQ_PATH%
	      mkdir %PRIVATE_PATH%
	      %~d0>%CATOP%\index.txt
    )
    if not exist %CA_KEY% (
	    echo "Making CA certificate ..."
	    echo %cd%
	    %GENKEY% -des3 -out %CA_KEY% %KEYLEN%
      %REQ% -new -x509 %CADAYS% -key %CA_KEY% -out %CA_CERT%
	    %CERT_CHECK% -in %CA_CERT%
	  )
	  goto exit

:newreq
    :: create a certificate request
    if not exist %DEV_KEY% (
        %GENKEY% -out %DEV_KEY% %KEYLEN%
    )
    %REQ% -new -key %DEV_KEY% -out %DEV_CERT_REQ%  %DAYS%
    echo "Request is in %DEV_CERT_REQ%, private key is in %DEV_KEY%"
    goto exit
:sign
    :: create a certificate
    if not exist %DEV_CERT_REQ% (
        echo "%DEV_CERT_REQ% doesnt exist, please run with -newreq first."
        exit 1
    )
    if not exist %CATOP%\serial (
	      set CREATE_SERIAL=-create_serial
    )

    %CA% %CREATE_SERIAL%  -in %DEV_CERT_REQ% -cert %CA_CERT% -keyfile %CA_KEY% -policy policy_anything -out %DEV_CERT%
    %CERT_CHECK% -in %DEV_CERT%
    echo "Signed certificate is in %DEV_CERT%"
    goto exit

:usage
 echo "usage: %0 -newca|-newreq|-sign [dev name] <config file>"
 echo "Example: 1. create CA: %0 -newca ca"
 echo "2. Create server cert req: %0 -newreq server"
 echo "3. Sign server cert req: %0 -sign server"
:exit

 


