package oni

import (
	"encoding/hex"
	"fmt"
	"github.com/ontio/ontology-crypto/keypair"
	"github.com/ontio/ontology-crypto/signature"
	"github.com/ontio/ontology-go-sdk/oni/types"
)

type Oni struct {
	oniClient OniClient
}

func NewOni() *Oni {
	return &Oni{oniClient: NewOniRestClient()}
}

func (this *Oni) SetRestAddr(restAddr string) {
	rest, ok := this.oniClient.(*OniRestClient)
	if ok {
		rest.SetAddress(restAddr)
	}
}

func NewOniWithAddr(restAddr string) *Oni {
	rest := NewOniRestClient()
	rest.SetAddress(restAddr)
	return &Oni{oniClient: rest}
}

// create oni account, return account private key and wallet file json string
// only support create default keyType and curve account
// TODO: ensure keyType and curve corresponding params string
func (this *Oni) NewAccount(pwd, label string, scheme signature.SignatureScheme,
	createOnly bool) (keypair.PrivateKey, string, error) {
	req := &types.NewAccountReq{
		Password:   pwd,
		Label:      label,
		KeyType:    "ecdsa",
		Curve:      "P-256",
		Scheme:     scheme.Name(),
		CreateOnly: createOnly,
	}
	resp, err := this.oniClient.NewAccount(req)
	if err != nil {
		return nil, "", err
	}
	privKey, err := keypair.WIF2Key([]byte(resp.PrivateKey))
	if err != nil {
		return nil, "", fmt.Errorf("NewAccount: parse priv key failed, err: %s", err)
	}
	return privKey, resp.Wallet, nil
}

func (this *Oni) GetCurrentAccount() (privKey keypair.PrivateKey, pubKey keypair.PublicKey, addr string,
	scheme signature.SignatureScheme, err error) {
	resp, err := this.oniClient.CurrentAccount()
	if err != nil {
		return
	}
	privKey, err = keypair.WIF2Key([]byte(resp.PrivateKey))
	if err != nil {
		err = fmt.Errorf("GetCurrentAccount: parse priv key failed, err: %s", err)
		return
	}
	pubKeyData, err := hex.DecodeString(resp.PublicKey)
	if err != nil {
		err = fmt.Errorf("GetCurrentAccount: decode pub key data failed, err: %s", err)
		return
	}
	pubKey, err = keypair.DeserializePublicKey(pubKeyData)
	if err != nil {
		err = fmt.Errorf("GetCurrentAccount: deserialize pub key failed, err: %s", err)
		return
	}
	scheme = resp.SigScheme
	return
}

func (this *Oni) Logout() error {
	return this.oniClient.Logout(&types.LogoutReq{})
}

func (this *Oni) ExportPrivKey(password string) (keypair.PrivateKey, error) {
	resp, err := this.oniClient.ExportPrivKey(password)
	if err != nil {
		return nil, err
	}
	privKey, err := keypair.WIF2Key([]byte(resp.PrivateKey))
	if err != nil {
		err = fmt.Errorf("ExportPrivKey: parse priv key failed, err: %s", err)
		return nil, err
	}
	return privKey, nil
}

func (this *Oni) ExportWalletFile() (string, error) {
	resp, err := this.oniClient.ExportWalletFile()
	if err != nil {
		return "", err
	}
	return resp.Wallet, nil
}

func (this *Oni) ImportWithPrivateKey()
