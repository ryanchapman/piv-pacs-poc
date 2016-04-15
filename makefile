# WARNING: will destroy all CA certs and keys!
cleanall:
	./make.bash cleanall

# Generate new root and intermediate CA certs and keys, if they do not already exist
ca:
	./make.bash ca

# Generate client certs
client:
	./make.bash client

# Write client certs to Yubikey (if one is plugged in)
yubikey:
	./make.bash yubikey
