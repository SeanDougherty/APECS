# Generate Cloud Key and Cert
openssl req \
	-newkey rsa:2048 -nodes -keyout cloud.key \
       	-x509 -days 365 -out cloud.crt \
	-subj "/C=US/ST=New York/L=Brooklyn/O=Example Cloud/CN=cloud.foo"

# Generate Provider Key and Cert
openssl req \
	-newkey rsa:2048 -nodes -keyout provider.key \
       	-x509 -days 365 -out provider.crt \
	-subj "/C=US/ST=New York/L=Brooklyn/O=Example Provider/CN=provider.foo"

# Generate EdgeServer Key and Cert
openssl req \
	-newkey rsa:2048 -nodes -keyout edgeserver.key \
       	-x509 -days 365 -out edgeserver.crt \
	-subj "/C=US/ST=New York/L=Brooklyn/O=Example EdgeServer/CN=edgeserver.foo"

# Generate User Key and Cert
openssl req \
	-newkey rsa:2048 -nodes -keyout user.key \
       	-x509 -days 365 -out user.crt \
	-subj "/C=US/ST=New York/L=Brooklyn/O=Example User/CN=user.foo"
