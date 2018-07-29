package wallet

import (
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/ontio/ontology-crypto/keypair"
	s "github.com/ontio/ontology-crypto/signature"
	"github.com/ontio/ontology/account"
	"github.com/ontio/ontology/core/types"
	"sync"
)

var DEFAULT_WALLET_NAME = "MyWallet"
var DEFAULT_WALLET_VERSION = "1.1"
var ERR_ACCOUNT_NOT_FOUND = errors.New("account not found")

type Wallet struct {
	Name          string
	Version       string
	scrypt        *keypair.ScryptParam
	accounts      []*account.AccountData
	identities    []*account.Identity
	defAcc        *account.AccountData
	accAddressMap map[string]*account.AccountData
	accLabelMap   map[string]*account.AccountData
	idMap         map[string]*account.Identity
	idLabelMap    map[string]*account.Identity
	extra         string
	path          string
	lock          sync.RWMutex
}

func NewWallet(path string) *Wallet {
	return &Wallet{
		Name:          DEFAULT_WALLET_NAME,
		Version:       DEFAULT_WALLET_VERSION,
		scrypt:        keypair.GetScryptParameters(),
		accounts:      make([]*account.AccountData, 0),
		accAddressMap: make(map[string]*account.AccountData),
		identities:    make([]*account.Identity, 0),
		idMap:         make(map[string]*account.Identity),
		idLabelMap:    make(map[string]*account.Identity),
		path:          path,
	}
}

func OpenWallet(path string) (*Wallet, error) {
	walletData := &account.WalletData{}
	err := walletData.Load(path)
	if err != nil {
		return nil, err
	}
	wallet := NewWallet(path)
	wallet.Name = walletData.Name
	wallet.Version = walletData.Version
	wallet.scrypt = walletData.Scrypt
	wallet.extra = walletData.Extra
	for _, accountData := range walletData.Accounts {
		if accountData.IsDefault {
			if wallet.defAcc != nil {
				return nil, fmt.Errorf("more than one default account")
			}
			wallet.defAcc = accountData
		}
		wallet.accounts = append(wallet.accounts, accountData)
		wallet.accAddressMap[accountData.Address] = accountData
		if accountData.Label != "" {
			_, ok := wallet.accLabelMap[accountData.Label]
			if ok {
				return nil, fmt.Errorf("duplicate account label:%s", accountData.Label)
			}
			wallet.accLabelMap[accountData.Label] = accountData
		}
	}
	if wallet.defAcc == nil && len(walletData.Accounts) > 0 {
		wallet.defAcc = walletData.Accounts[0]
	}
	for _, identity := range walletData.Identities {
		wallet.identities = append(wallet.identities, &identity)
		wallet.idMap[identity.ID] = &identity
		if identity.Label != "" {
			_, ok := wallet.idLabelMap[identity.Label]
			if ok {
				return nil, fmt.Errorf("duplicate identity label:%s", identity.Label)
			}
			wallet.idLabelMap[identity.Label] = &identity
		}
	}
	return wallet, nil
}

func (this *Wallet) NewAccount(keyType keypair.KeyType, curveCode byte, sigScheme s.SignatureScheme, passwd []byte) (*account.Account, error) {
	if len(passwd) == 0 {
		return nil, fmt.Errorf("password cannot empty")
	}
	prvkey, pubkey, err := keypair.GenerateKeyPair(keyType, curveCode)
	if err != nil {
		return nil, fmt.Errorf("generateKeyPair error:%s", err)
	}
	address := types.AddressFromPubKey(pubkey)
	addressBase58 := address.ToBase58()
	prvSecret, err := keypair.EncryptPrivateKey(prvkey, addressBase58, passwd)
	if err != nil {
		return nil, fmt.Errorf("encryptPrivateKey error:%s", err)
	}
	accData := &account.AccountData{}
	accData.SetKeyPair(prvSecret)
	accData.SigSch = sigScheme.Name()
	accData.PubKey = hex.EncodeToString(keypair.SerializePublicKey(pubkey))
	if !this.checkSigScheme(accData.Alg, sigScheme) {
		return nil, fmt.Errorf("sigScheme:%s does not match with KeyType:%s", sigScheme.Name(), accData.Alg)
	}
	err = this.addAccountData(accData)
	if err != nil {
		return nil, err
	}
	return &account.Account{
		PrivateKey: prvkey,
		PublicKey:  pubkey,
		Address:    address,
		SigScheme:  sigScheme,
	}, nil
}

func (this *Wallet) NewDefaultSetAccount(passwd []byte) (*account.Account, error) {
	return this.NewAccount(keypair.PK_ECDSA, keypair.P256, s.SHA256withECDSA, passwd)
}

func (this *Wallet) NewAccountFromWIF(wif, passwd []byte) (*account.Account, error) {
	if len(passwd) == 0 {
		return nil, fmt.Errorf("password cannot empty")
	}
	prvKey, err := keypair.GetP256KeyPairFromWIF(wif)
	if err != nil {
		return nil, fmt.Errorf("GetP256KeyPairFromWIF error:%s", err)
	}
	pubKey := prvKey.Public()
	address := types.AddressFromPubKey(pubKey)
	addressBase58 := address.ToBase58()
	prvSecret, err := keypair.EncryptPrivateKey(prvKey, addressBase58, passwd)
	if err != nil {
		return nil, fmt.Errorf("encryptPrivateKey error:%s", err)
	}
	accData := &account.AccountData{}
	accData.SetKeyPair(prvSecret)
	accData.SigSch = s.SHA256withECDSA.Name()
	accData.PubKey = hex.EncodeToString(keypair.SerializePublicKey(pubKey))
	err = this.addAccountData(accData)
	if err != nil {
		return nil, err
	}
	return &account.Account{
		PrivateKey: prvKey,
		PublicKey:  pubKey,
		Address:    address,
		SigScheme:  s.SHA256withECDSA,
	}, nil
}

func (this *Wallet) SetDefaultAccount(address string) error {
	this.lock.Lock()
	defer this.lock.Unlock()
	accData, ok := this.accAddressMap[address]
	if !ok {
		return ERR_ACCOUNT_NOT_FOUND
	}
	this.defAcc = accData
	return nil
}

func (this *Wallet) GetDefaultAccount(passwd []byte) (*account.Account, error) {
	if this.defAcc == nil {
		return nil, fmt.Errorf("does not set default account")
	}
	return this.GetAccountFromAccountData(this.defAcc, passwd)
}

func (this *Wallet) GetAccountByAddress(address string, passwd []byte) (*account.Account, error) {
	accData, err := this.GetAccountDataByAddress(address)
	if err != nil {
		return nil, err
	}
	return this.GetAccountFromAccountData(accData, passwd)
}

func (this *Wallet) GetAccountByLabel(label string, passwd []byte) (*account.Account, error) {
	accData, err := this.GetAccountDataByLabel(label)
	if err != nil {
		return nil, err
	}
	return this.GetAccountFromAccountData(accData, passwd)
}

//Index start from 1
func (this *Wallet) GetAccountByIndex(index int, passwd []byte) (*account.Account, error) {
	accData, err := this.GetAccountDataByIndex(index)
	if err != nil {
		return nil, err
	}
	return this.GetAccountFromAccountData(accData, passwd)
}

func (this *Wallet) GetAccountCount() int {
	this.lock.RLock()
	defer this.lock.RUnlock()
	return len(this.accounts)
}

func (this *Wallet) GetAccountDataByAddress(address string) (*account.AccountData, error) {
	this.lock.RLock()
	defer this.lock.RUnlock()
	accData, ok := this.accAddressMap[address]
	if !ok {
		return nil, ERR_ACCOUNT_NOT_FOUND
	}
	return this.CloneAccountData(accData), nil
}

func (this *Wallet) GetAccountDataByLabel(label string) (*account.AccountData, error) {
	if label == "" {
		return nil, fmt.Errorf("cannot found account by empty label")
	}
	accData, ok := this.accLabelMap[label]
	if !ok {
		return nil, ERR_ACCOUNT_NOT_FOUND
	}
	return this.CloneAccountData(accData), nil
}

//Index start from 1
func (this *Wallet) GetAccountDataByIndex(index int) (*account.AccountData, error) {
	this.lock.RLock()
	defer this.lock.RUnlock()
	if index <= 0 || index > len(this.accounts) {
		return nil, fmt.Errorf("index out of range")
	}
	accData := this.accounts[index-1]
	return this.CloneAccountData(accData), nil
}

func (this *Wallet) CloneAccountData(accData *account.AccountData) *account.AccountData {
	newAccData := &account.AccountData{
		Label:     accData.Label,
		PubKey:    accData.PubKey,
		SigSch:    accData.SigSch,
		IsDefault: accData.IsDefault,
		Lock:      accData.Lock,
	}
	newAccData.SetKeyPair(accData.GetKeyPair())
	return newAccData
}

func (this *Wallet) SetLabel(address, newLabel string) error {
	this.lock.RLock()
	defer this.lock.RUnlock()
	accData, ok := this.accAddressMap[address]
	if !ok {
		return ERR_ACCOUNT_NOT_FOUND
	}
	accData.Label = newLabel
	return nil
}

func (this *Wallet) SetSigScheme(address string, sigScheme s.SignatureScheme) error {
	this.lock.RLock()
	defer this.lock.RUnlock()
	accData, ok := this.accAddressMap[address]
	if !ok {
		return ERR_ACCOUNT_NOT_FOUND
	}
	if !this.checkSigScheme(accData.Alg, sigScheme) {
		return fmt.Errorf("sigScheme:%s does not match with KeyType:%s", sigScheme.Name(), accData.Alg)
	}
	accData.SigSch = sigScheme.Name()
	return nil
}

func (this *Wallet) ChangePassword(address string, oldPassword, newPassword []byte) error {
	this.lock.Lock()
	defer this.lock.Unlock()
	accData, ok := this.accAddressMap[address]
	if !ok {
		return ERR_ACCOUNT_NOT_FOUND
	}
	protectedkey, err := keypair.ReencryptPrivateKey(&accData.ProtectedKey, oldPassword, newPassword, this.scrypt, this.scrypt)
	if err != nil {
		return err
	}
	accData.SetKeyPair(protectedkey)
	return nil
}

func (this *Wallet) addAccountData(accountData *account.AccountData) error {
	this.lock.Lock()
	defer this.lock.Unlock()
	_, ok := this.accAddressMap[accountData.Address]
	if ok {
		return nil
	}
	if this.defAcc != nil && accountData.IsDefault {
		return fmt.Errorf("already have default account")
	}
	if accountData.Label != "" {
		_, ok := this.accLabelMap[accountData.Label]
		if ok {
			return fmt.Errorf("duplicate account label:%s", accountData.Label)
		}
		this.accLabelMap[accountData.Label] = accountData
	}
	if len(this.accounts) == 0 {
		accountData.IsDefault = true
	}
	if this.defAcc == nil && accountData.IsDefault {
		this.defAcc = accountData
	}
	this.accAddressMap[accountData.Address] = accountData
	this.accounts = append(this.accounts, accountData)
	return nil
}

func (this *Wallet) DeleteAccount(address string) error {
	this.lock.Lock()
	defer this.lock.Unlock()
	accData, ok := this.accAddressMap[address]
	if !ok {
		return ERR_ACCOUNT_NOT_FOUND
	}
	if accData.IsDefault {
		return fmt.Errorf("cannot delete default account")
	}
	delete(this.accAddressMap, address)
	if accData.Label != "" {
		delete(this.accLabelMap, accData.Label)
	}
	return nil
}

func (this *Wallet) GetAccountFromAccountData(accData *account.AccountData, pwd []byte) (*account.Account, error) {
	privateKey, err := keypair.DecryptWithCustomScrypt(&accData.ProtectedKey, pwd, this.scrypt)
	if err != nil {
		return nil, fmt.Errorf("decrypt PrivateKey error:%s", err)
	}
	publicKey := privateKey.Public()
	addr := types.AddressFromPubKey(publicKey)
	scheme, err := s.GetScheme(accData.SigSch)
	if err != nil {
		return nil, fmt.Errorf("signature scheme error:%s", err)
	}
	return &account.Account{
		PrivateKey: privateKey,
		PublicKey:  publicKey,
		Address:    addr,
		SigScheme:  scheme,
	}, nil
}

func (this *Wallet) checkSigScheme(algorithm string, sigScheme s.SignatureScheme) bool {
	switch algorithm {
	case "ECDSA":
		switch sigScheme {
		case s.SHA224withECDSA:
		case s.SHA256withECDSA:
		case s.SHA384withECDSA:
		case s.SHA512withECDSA:
		case s.SHA3_224withECDSA:
		case s.SHA3_256withECDSA:
		case s.SHA3_384withECDSA:
		case s.SHA3_512withECDSA:
		case s.RIPEMD160withECDSA:
		default:
			return false
		}
	case "SM2":
		switch sigScheme {
		case s.SM3withSM2:
		default:
			return false
		}
	case "Ed25519":
		switch sigScheme {
		case s.SHA512withEDDSA:
		default:
			return false
		}
	default:
		return false
	}
	return true
}

func (this *Wallet) Save() error {
	walletData := &account.WalletData{
		Name:       this.Name,
		Version:    this.Version,
		Scrypt:     this.scrypt,
		Identities: make([]account.Identity, 0),
		Accounts:   make([]*account.AccountData, 0),
		Extra:      this.extra,
	}
	for _, identity := range this.identities {
		walletData.Identities = append(walletData.Identities, *identity)
	}
	for _, acc := range this.accounts {
		walletData.Accounts = append(walletData.Accounts, acc)
	}
	return walletData.Save(this.path)
}
