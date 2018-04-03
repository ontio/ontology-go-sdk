package ontology_go_sdk

import (
	sdkcom "github.com/ontio/ontology-go-sdk/common"
	"github.com/ontio/ontology-go-sdk/rpc"
	"github.com/ontio/ontology-go-sdk/wallet"
)

type OntologySdk struct {
	cryptScheme string
	Wallet      *wallet.OntWallet
	Rpc         *rpc.RpcClient
}

func NewOntologySdk() *OntologySdk {
	return &OntologySdk{
		cryptScheme: sdkcom.CRYPTO_SCHEME_DEFAULT,
		Rpc:         rpc.NewRpcClient(sdkcom.CRYPTO_SCHEME_DEFAULT),
		Wallet:      wallet.NewOntWallet(sdkcom.CRYPTO_SCHEME_DEFAULT),
	}
}

func (this *OntologySdk) GetCryptScheme() string {
	return this.cryptScheme
}

func (this *OntologySdk) SetCryptScheme(scheme string) {
	this.cryptScheme = scheme
	this.Wallet.SetCryptScheme(scheme)
}
