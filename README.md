# ontology-go-sdk

ontology-go-sdk is a client to operation with ontology. ontology-go-sdk was be designed to easy use.
ontology-go-sdk contain rpc api、restful api and wallet api.

## How to use?

First of all, Create OntologySDK instance by NewOntologySdk method.

`sdk := NewOntologySdk()`

Then, set rpc server address.

`sdk.SetAddress("http://localhost:20336")`

Then, call rpc server through sdk instance.

`sdk.Rpc.GetVersion()`
