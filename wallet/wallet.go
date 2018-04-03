package wallet

import (
	"fmt"
	"github.com/ontio/ontology/account"
	"os"
)

type OntWallet struct {
	cryptScheme string
	wallet      *account.ClientImpl
}

func NewOntWallet(cryptScheme string) *OntWallet {
	return &OntWallet{
		cryptScheme: cryptScheme,
	}
}

func (this *OntWallet) SetCryptScheme(cryptScheme string) {
	this.cryptScheme = cryptScheme
}

func (this *OntWallet) OpenOrCreateWallet(walletFile, pwd string) error {
	if this.isFileExist(walletFile) {
		return this.OpenWallet(walletFile, pwd)
	} else {
		return this.CreateWallet(walletFile, pwd)
	}
}

func (this *OntWallet) CreateWallet(walletFile, pwd string) error {
	wallet := account.Create(walletFile, this.cryptScheme, []byte(pwd))
	if wallet == nil {
		return fmt.Errorf("CreateWallet:%s failed", walletFile)
	}
	this.wallet = wallet
	return nil
}

func (this *OntWallet) OpenWallet(walletFile, pwd string) error {
	wallet := account.Open(walletFile, []byte(pwd))
	if wallet == nil {
		return fmt.Errorf("OpenWallet:%s failed", walletFile)
	}
	this.wallet = wallet
	return nil
}

func (this *OntWallet)GetDefaultAccount()(*account.Account, error){
	return this.wallet.GetDefaultAccount()
}

func (this *OntWallet) CreateAccount() (*account.Account, error) {
	return this.wallet.CreateAccount(this.cryptScheme)
}

func (this *OntWallet)ChangePassword(old, new string)error{
	res := this.wallet.ChangePassword([]byte(old), []byte(new))
	if !res {
		return fmt.Errorf("ChangePassword failed")
	}
	return nil
}

func (this *OntWallet) isFileExist(file string) bool {
	_, err := os.Stat(file)
	return err == nil || os.IsExist(err)
}
