# APECS: A Distributed Access Control Framework for Pervasive Edge Computing Services

A C++ project that implements APECS, an advanced access control framework for the Pervasive Edge Computing (PEC) environment, which allows legitimate users to utilize any available edge services without need for communication beyond the network edge.

For further details [see our paper](https://doi.org/10.1145/3460120.3484804).


## Dependencies

[Pairing-Based Cryptography (PBC) library (v.0.5.14) ](https://crypto.stanford.edu/pbc/)

[C programming language (v.9.3.0)](https://www.iso.org/standard/74528.html)

[C++ libssl-dev library (v.1.1.1)](https://packages.ubuntu.com/search?keywords=libssl-dev&searchon=names&suite=all&section=all)

[gRPC framework (v.1.20.0)](https://grpc.io/docs/languages/cpp/)

[mongoDB Database (v.4.2.9)](https://www.mongodb.com/)

[mongoDB C++ Driver ()](https://docs.mongodb.com/drivers/cxx/)


## Deployment on GENI (No dependency installation necessary)

This requires some basic skills with the GENI dashboard, as well as membership to an organization that maintains access to GENI.
Create 4 instageni nodes, all pointing to this Disk Image:
`https://www.instageni.colorado.edu/image_metadata.php?uuid=bd570e51-13e2-11eb-b2a6-000099989701`.
To mimic the topography of the edge, host these images on three different sites. (One site will have two nodes). 
After all 4 have been spun up successfully, we will need to reinstall some aspects of our dependencies. This is due to the nature that GENI snapshots do not save group permissions nor do they save the contents of the home directory.

### Uninstalling and Reinstalling MongoDB

From the home directory of each InstaGENI node, run the following commands.

`sudo apt-get purge mongodb-org* `

This first command above may freeze at processing triggers for man-db, that is normal. It should end within 5 or so minutes, in which time you can be opening up the other 3 nodes and beginning this process on them as well! If it has been going for longer than 10 minutes, feel free to try and Ctrl-C out of the process, if Ctrl-C doesn't work just wait. If it still is hanging at 15 minutes, try completely closing and reopening the terminal and running the command again.

```
sudo rm -r /var/log/mongodb
sudo rm -r /var/lib/mongodb

wget -qO - https://www.mongodb.org/static/pgp/server-4.4.asc | sudo apt-key add -

echo "deb [ arch=amd64,arm64 ] https://repo.mongodb.org/apt/ubuntu bionic/mongodb-org/4.4 multiverse" | sudo tee /etc/apt/sources.list.d/mongodb-org-4.4.list

sudo apt-get update

sudo apt-get install -y mongodb-org

sudo service mongod start

sudo service mongod status
```

### Installing Python-pip and Pybind11

Similarly, pip libraries and pybind11 don't like to transfer across images. Thankfully they are pretty easy to just install.

```
sudo apt-get install python-pip python3-pip -y

pip install pybind11 && pip3 install pybind11
```

### Unpacking the home folder

Finally, we can restore the home directory.

Simply clone this repository into the home directory of each InstaGENI node.

### Prepping the project

This project in particular has 4 actors. A receiving Cloud server, a Sending and Receiving Provider server, a Sending and Receiving EdgeServer, and a Sending User client.

We can cd into each of them on the appropriate nodes and begin updating the IPs they use to talk to each other.

Cloud node:
```
$ cd ./src/containers/Cloud/
$ make
```
Provider node:
```
$ cd ./src/containers/Provider/
$ vim Provider.cc
```
Note: for Provider, scroll through the document, looking for "0.0.0.0", on each line, notice if it is talking to the Cloud/BackEnd Service or to EdgeService and update the "0.0.0.0" portion to the appropriate IP. Save the doc and run the final command below
```
$ make
```
EdgeServer node:
```
$ cd ./src/containers/EdgeServer/
$ vim EdgeServer.h
```
Note: page-down to the end of the document and update the provider and cloud ips. save your changes and then run the next command
```
$ make
```
User node:
```
$ cd ./src/containers/User/
$ vim User.cc
```
Note: scroll through the document, looking for "0.0.0.0", on each line, notice if it is talking to the EdgeServer Service or to the Provider service and update the "0.0.0.0" portion to the appropriate IP. Save the doc and run the final command below
```
$ make
```
### Testing the Project

Finally, we can test the communication in this project.

To test the project run these commands:

Cloud:
```
$ ./bes
```

Provider:
```
$ ./provider
$ 2
```

EdgeServer:
```
$ ./es
```

User:
```
$ ./user --prompt
$ 1
$ 2
$ lorem.txt
$ 3
$ 0
```
Done! 

