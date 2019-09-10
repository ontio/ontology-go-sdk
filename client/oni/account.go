package oni

import "fmt"

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

type LogoutReq struct {
}

type ExportWallet struct {
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

func GenExportPrivKeyUrlWithPwd(pwd string) string {
	return fmt.Sprintf(URL_EXPORT_PRIV_KEY, pwd)
}

func GenBalanceUrlWithAddress(base58Addr string) string {
	return fmt.Sprintf(URL_ACCOUNT_BALANCE, base58Addr)
}
