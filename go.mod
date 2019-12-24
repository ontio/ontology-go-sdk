module github.com/ontio/ontology-go-sdk

go 1.12

require (
	github.com/btcsuite/btcd v0.20.1-beta // indirect
	github.com/gorilla/websocket v1.4.1
	github.com/itchyny/base58-go v0.1.0
	github.com/ontio/go-bip32 v0.0.0-20190520025953-d3cea6894a2b
	github.com/ontio/ontology v1.8.1
	github.com/ontio/ontology-crypto v1.0.7
	github.com/stretchr/testify v1.4.0
	github.com/tyler-smith/go-bip39 v1.0.2
	golang.org/x/crypto v0.0.0-20191219195013-becbf705a915
)

replace github.com/go-interpreter/wagon => github.com/ontio/wagon v0.3.1-0.20191012103353-ef8d35ecd300
