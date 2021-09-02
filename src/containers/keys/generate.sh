# Generate CA key:
openssl genrsa -out ca.key 4096

# Generate CA certificate:
openssl req -new -x509 -days 365 -key ca.key -out ca.crt -sha256 -subj "/C=US/ST=New York/L=Brooklyn/O=Example CA/CN=ca.foo"


# Generate Cloud key:
openssl genrsa -out cloud.key 4096

# Generate Cloud signing request:
openssl req -new -key cloud.key -out cloud.csr -subj "/C=US/ST=New York/L=Brooklyn/O=Example Cloud/CN=cloud.foo"

# Self-sign Cloud certificate:
openssl x509 -req -days 365 -in cloud.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out cloud.crt

# Remove passphrase from the server key:
openssl rsa -in cloud.key -out cloud.key


# Generate Provider key:
openssl genrsa -out provider.key 4096

# Generate provider signing request:
openssl req -new -key provider.key -out provider.csr -subj "/C=US/ST=New York/L=Brooklyn/O=Example Provider/CN=provider.foo"

# Self-sign provider certificate:
openssl x509 -req -days 365 -in provider.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out provider.crt

# Remove passphrase from the provider key:
openssl rsa -in provider.key -out provider.key


# Generate EdgeServer key:
openssl genrsa -out edgeserver.key 4096

# Generate EdgeServer signing request:
openssl req -new -key edgeserver.key -out edgeserver.csr -subj "/C=US/ST=New York/L=Brooklyn/O=Example EdgeServer/CN=edgeserver.foo"

# Self-sign EdgeServer certificate:
openssl x509 -req -days 365 -in edgeserver.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out edgeserver.crt

# Remove passphrase from the EdgeServer key:
openssl rsa -in edgeserver.key -out edgeserver.key


# Generate User key:
openssl genrsa -out user.key 4096

# Generate User signing request:
openssl req -new -key user.key -out user.csr -subj "/C=US/ST=New York/L=Brooklyn/O=Example User/CN=user.foo" 

# Self-sign User certificate:
openssl x509 -req -days 365 -in user.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out user.crt

# Remove passphrase from the User key:
openssl rsa -in user.key -out user.key
