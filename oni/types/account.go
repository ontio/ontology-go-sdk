package types

import (
	"fmt"
	"github.com/ontio/ontology-crypto/signature"
)

type AccountMgr interface {
	NewAccount(req *NewAccountReq) (*NewAccountResp, error)
	CurrentAccount() (*CurrentAccountResp, error)
	Logout(req *LogoutReq) error
	ExportPrivKey(password string) (*ExportPrivKeyResp, error)
	ExportWalletFile() (*ExportWalletResp, error)
	ImportAccountWithWalletFile(req *ImportAccWithWalletReq) error
	ImportAccountWithPrivKey(req *ImportAccWithPrivKeyReq) error
	Balance(base58Addr string) (*BalanceResp, error)
}

const (
	URL_NEW_ACCOUNT          = "/api/v1/account"
	URL_CURRENT_ACCOUNT      = "/api/v1/account"
	URL_LOGOUT               = "/api/v1/account/logout"
	URL_EXPORT_PRIV_KEY      = "/api/v1/account/export/privatekey/%s"
	URL_EXPORT_WALLET        = "/api/v1/account/export/walletfile"
	URL_IMPORT_WITH_WALLET   = "/api/v1/account/import/walletfile"
	URL_IMPORT_WITH_PRIV_KEY = "/api/v1/account/import/privatekey"
	URL_ACCOUNT_BALANCE      = "/api/v1/balance/%s"
)

type NewAccountReq struct {
	Password   string
	Label      string
	KeyType    string
	Curve      string
	Scheme     string
	CreateOnly bool
}

type NewAccountResp struct {
	PrivateKey string
	Wallet     string
	Label      string
}

type CurrentAccountResp struct {
	PrivateKey string
	PublicKey  string
	Address    string
	SigScheme  signature.SignatureScheme
	Label      string
	Wallet     string
}

type LogoutReq struct {
}

type ExportPrivKeyResp struct {
	PrivateKey string
}

type ExportWalletResp struct {
	Wallet string
}

type ImportAccWithWalletReq struct {
	Wallet   string
	Password string
}

type ImportAccWithPrivKeyReq struct {
	PrivateKey string
	Password   string
	Label      string
}

type Balance struct {
	Name     string
	Symbol   string
	Decimals uint64
	Balance  string
}

type BalanceResp []*Balance

func GenExportPrivKeyUrl(pwd string) string {
	return fmt.Sprintf(URL_EXPORT_PRIV_KEY, pwd)
}

func GenBalanceUrl(base58Addr string) string {
	return fmt.Sprintf(URL_ACCOUNT_BALANCE, base58Addr)
}
