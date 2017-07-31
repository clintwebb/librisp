#!/bin/bash

echo "This script will create the various certificates required to "
echo "validate encrypted communication between the server and client tools"
echo

echo "This script will create "
echo "  a root Certificate Authority."
echo "  a CA for signing Client certificates"
echo "  a Server certificate (and key)."
echo "  a Client certificate (and key)."
echo

ROOT_CONFIG=root-openssl.cnf
INT_CONFIG=int-openssl.cnf

if [ ! -e $ROOT_CONFIG ]; then
  echo "Config file for OpenSSL ROOT does not exist."
  echo "Where did it go?"
  echo "It is required to create the Intermediate and then other certificates."
  sleep 1
  exit 1
fi


touch root-index.txt
test -e root-serial || echo "1000" > root-serial
test -e root-crlnumber || echo "1000" > root-crlnumber


ROOT_CA_KEY=root-ca.key.pem
ROOT_CA_CERT=root-ca.cert.pem

echo "First generating a Key for the Root CA"
test -e $ROOT_CA_KEY || openssl genrsa -aes256 -out $ROOT_CA_KEY 4096
chmod 400 $ROOT_CA_KEY

echo "Now using the Root CA Key to create the Root Certificate"
test -e $ROOT_CA_CERT || openssl req -new -x509 -days 7300 -sha256 -extensions v3_ca -key $ROOT_CA_KEY -out $ROOT_CA_CERT
chmod 444 $ROOT_CA_CERT


touch int-index.txt
test -e int-serial || echo "1000" > int-serial
test -e int-crlnumber || echo "1000" > int-crlnumber

if [ ! -e $INT_CONFIG ]; then
  echo "Config file for OpenSSL INTERMEDIATE does not exist."
  echo "Where did it go?"
  sleep 1
  exit 1
fi

INT_CA_KEY=int-ca.key.pem
INT_CA_CERT=int-ca.cert.pem
INT_CA_CSR=int-ca.csr.pem

echo "Creating Intermediate CA signed by the root.  This will be used to sign the client and server certificate requests."
echo.

echo;echo "Creating Intermediate Key."
test -e $INT_CA_KEY || openssl genrsa -aes256 -out $INT_CA_KEY 4096
chmod 400 $INT_CA_KEY

echo "Creating the Intermediate CSR"
test -e $INT_CA_CSR || openssl req -config $INT_CONFIG -new -sha256 -key $INT_CA_KEY -out $INT_CA_CSR

echo "Signing Intermediate CSR with ROOT CA"
test -e $INT_CA_CERT || openssl ca -config $ROOT_CONFIG -extensions v3_intermediate_ca \
      -days 3650 -notext -md sha256 \
      -in $INT_CA_CSR \
      -out $INT_CA_CERT

echo "Verifying Cert."
openssl verify -CAfile $ROOT_CA_CERT $INT_CA_CERT

echo "Creating Certificate Chain FIle"
chmod 644 ca-chain.cert.pem
cat $ROOT_CA_CERT > ca-chain.cert.pem
cat $INT_CA_CERT >> ca-chain.cert.pem
chmod 444 ca-chain.cert.pem

echo "Creating Server cert key"
test -e server.key.pem || openssl genrsa -out server.key.pem 2048
chmod 400 server.key.pem

echo "Creating the Server CSR"
test -e server.csr.pem || openssl req -config $INT_CONFIG -key server.key.pem -new -sha256 -out server.csr.pem

echo "Signing the Server CSR with the Intermediate certificate."
test -e server.cert.pem || openssl ca -config $INT_CONFIG -extensions server_cert  -days 375 -notext -md sha256 -in server.csr.pem -out server.cert.pem 
test -e server.cert.pem || (echo "Failed to create server cert."; sleep 2; exit 1)
chmod 444 server.cert.pem

# Normally the client will do this.  The server side does not need to know the key.
echo "Creating Client cert key"
test -e client.key.pem || openssl genrsa -aes256 -out client.key.pem 2048
chmod 400 client.key.pem

echo "Creating the Client CSR"
test -e client.csr.pem || openssl req -config $INT_CONFIG -key client.key.pem -new -sha256 -out client.csr.pem

echo "Signing the Client CSR with the Intermediate certificate."
test -e client.cert.pem || openssl ca -config $INT_CONFIG -extensions usr_cert -days 375 -notext -md sha256 -in client.csr.pem -out client.cert.pem 
test -e client.cert.pem || (echo "Failed to create client cert."; sleep 2; exit 1)
chmod 444 client.cert.pem
