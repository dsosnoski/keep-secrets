# create a default OpenSSL certificate authority directory structure
mkdir -p demoCA/private demoCA/newcerts; echo '01' > demoCA/serial; touch demoCA/index.txt
# create the private-public key pair for the certificate authority
openssl genrsa -out ca-keypair.pem 2048
# export the private key into the directory structure
openssl pkey -in ca-keypair.pem -out demoCA/private/cakey.pem
# create a self-signed certificate good for 10 years for the certificate authority
echo "Answer the following questions for your certificate authority"
read -p "Press [Enter] key to continue"
openssl req -new -x509 -days 3650 -key ca-keypair.pem -sha256 -out demoCA/cacert.pem

# create the private-public key pair for the user, and export the certificate request
#  (run on the system which will own the certificate)
openssl genrsa -out user-keypair.pem 2048
echo "Answer the following questions for the user"
read -p "Press [Enter] key to continue"
openssl req -new -key user-keypair.pem -sha256 -out user-cert.req

# sign the user certificate (run on the certificate authority system)
echo "Answer the following questions for your certificate authority"
read -p "Press [Enter] key to continue"
if openssl ca -out user-cert.crt -policy policy_anything -md sha256 -infiles user-cert.req ; then echo "Done!"
fi
