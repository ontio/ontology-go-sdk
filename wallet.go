package ontology_go_sdk

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/ontio/ontology-crypto/keypair"
	s "github.com/ontio/ontology-crypto/signature"
	"github.com/ontio/ontology/common"
	"github.com/ontio/ontology/core/types"
	"io/ioutil"
	"os"
	"sync"
)

var DEFAULT_WALLET_NAME = "MyWallet"
var DEFAULT_WALLET_VERSION = "1.1"
var ERR_ACCOUNT_NOT_FOUND = errors.New("account not found")
var ERR_IDENTITY_NOT_FOUND = errors.New("identity not found")
var ERR_CONTROLLER_NOT_FOUND = errors.New("controller not found")

type Wallet struct {
	Name             string
	Version          string
	Scrypt           *keypair.ScryptParam
	Extra            string
	accounts         []*AccountData
	identities       []*Identity
	defAcc           *AccountData
	accAddressMap    map[string]*AccountData
	accLabelMap      map[string]*AccountData
	identityMap      map[string]*Identity
	identityLabelMap map[string]*Identity
	defIdentity      *Identity
	path             string
	ontSdk           *OntologySdk
	lock             sync.RWMutex
}

func NewWallet(path string) *Wallet {
	return &Wallet{
		Name:             DEFAULT_WALLET_NAME,
		Version:          DEFAULT_WALLET_VERSION,
		Scrypt:           keypair.GetScryptParameters(),
		accounts:         make([]*AccountData, 0),
		accAddressMap:    make(map[string]*AccountData),
		accLabelMap:      make(map[string]*AccountData),
		identities:       make([]*Identity, 0),
		identityMap:      make(map[string]*Identity),
		identityLabelMap: make(map[string]*Identity),
		path:             path,
	}
}

func OpenWallet(path string) (*Wallet, error) {
	walletData := &WalletData{}
	err := walletData.Load(path)
	if err != nil {
		return nil, err
	}
	wallet := NewWallet(path)
	wallet.Name = walletData.Name
	wallet.Version = walletData.Version
	wallet.Scrypt = walletData.Scrypt
	wallet.Extra = walletData.Extra
	for _, accountData := range walletData.Accounts {
		accountData.scrypt = wallet.Scrypt
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

	for _, identityData := range walletData.Identities {
		identityData.scrypt = wallet.Scrypt
		identity, err := NewIdentityFromIdentityData(identityData)
		if err != nil {
			return nil, fmt.Errorf("NewIdentityFromIdentityData error:%s", err)
		}
		if identity.IsDefault {
			if wallet.defIdentity != nil {
				return nil, fmt.Errorf("more than one default identity")
			}
			wallet.defIdentity = identity
		}
		wallet.identities = append(wallet.identities, identity)
		wallet.identityMap[identity.ID] = identity
		if identity.Label != "" {
			_, ok := wallet.identityLabelMap[identity.Label]
			if ok {
				return nil, fmt.Errorf("duplicate identity label:%s", identity.Label)
			}
			wallet.identityLabelMap[identity.Label] = identity
		}
	}
	if wallet.defIdentity == nil && len(wallet.identities) > 0 {
		wallet.defIdentity = wallet.identities[0]
	}
	return wallet, nil
}

func (this *Wallet) NewAccount(keyType keypair.KeyType, curveCode byte, sigScheme s.SignatureScheme, passwd []byte) (*Account, error) {
	accData, err := NewAccountData(keyType, curveCode, sigScheme, passwd, this.Scrypt)
	if err != nil {
		return nil, err
	}
	err = this.AddAccountData(accData)
	if err != nil {
		return nil, err
	}
	return accData.GetAccount(passwd)
}

func (this *Wallet) NewDefaultSettingAccount(passwd []byte) (*Account, error) {
	return this.NewAccount(keypair.PK_ECDSA, keypair.P256, s.SHA256withECDSA, passwd)
}

func (this *Wallet) NewAccountFromWIF(wif, passwd []byte) (*Account, error) {
	if len(passwd) == 0 {
		return nil, fmt.Errorf("password cannot empty")
	}
	prvkey, err := keypair.GetP256KeyPairFromWIF(wif)
	if err != nil {
		return nil, fmt.Errorf("GetP256KeyPairFromWIF error:%s", err)
	}
	pubKey := prvkey.Public()
	address := types.AddressFromPubKey(pubKey)
	addressBase58 := address.ToBase58()
	prvSecret, err := keypair.EncryptWithCustomScrypt(prvkey, addressBase58, passwd, this.Scrypt)
	if err != nil {
		return nil, fmt.Errorf("encryptPrivateKey error:%s", err)
	}
	accData := &AccountData{}
	accData.SetKeyPair(prvSecret)
	accData.SigSch = s.SHA256withECDSA.Name()
	accData.PubKey = hex.EncodeToString(keypair.SerializePublicKey(pubKey))
	accData.SetScript(this.Scrypt)
	err = this.AddAccountData(accData)
	if err != nil {
		return nil, err
	}
	return &Account{
		PrivateKey: prvkey,
		PublicKey:  pubKey,
		Address:    address,
		SigScheme:  s.SHA256withECDSA,
	}, nil
}

func (this *Wallet) AddAccountData(accountData *AccountData) error {
	if !ScryptEqual(accountData.scrypt, this.Scrypt) {
		return fmt.Errorf("scrypt unmatch")
	}
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
	if this.defAcc == nil {
		accountData.IsDefault = true
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
	size := len(this.accounts)
	for index, accountData := range this.accounts {
		if accData.Address != accountData.Address {
			continue
		}
		if size-1 == index {
			this.accounts = this.accounts[:index]
		} else {
			this.accounts = append(this.accounts[:index], this.accounts[index+1:]...)
		}
		break
	}
	return nil
}

func (this *Wallet) SetDefaultAccount(address string) error {
	this.lock.Lock()
	defer this.lock.Unlock()
	accData, ok := this.accAddressMap[address]
	if !ok {
		return ERR_ACCOUNT_NOT_FOUND
	}
	if this.defAcc != nil {
		this.defAcc.IsDefault = false
	}
	accData.IsDefault = true
	this.defAcc = accData
	return nil
}

func (this *Wallet) GetDefaultAccount(passwd []byte) (*Account, error) {
	this.lock.RLock()
	defer this.lock.RUnlock()
	if this.defAcc == nil {
		return nil, fmt.Errorf("does not set default account")
	}
	return this.defAcc.GetAccount(passwd)
}

func (this *Wallet) GetAccountByAddress(address string, passwd []byte) (*Account, error) {
	accData, err := this.GetAccountDataByAddress(address)
	if err != nil {
		return nil, err
	}
	return accData.GetAccount(passwd)
}

func (this *Wallet) GetAccountByLabel(label string, passwd []byte) (*Account, error) {
	accData, err := this.GetAccountDataByLabel(label)
	if err != nil {
		return nil, err
	}
	return accData.GetAccount(passwd)
}

//Index start from 1
func (this *Wallet) GetAccountByIndex(index int, passwd []byte) (*Account, error) {
	accData, err := this.GetAccountDataByIndex(index)
	if err != nil {
		return nil, err
	}
	return accData.GetAccount(passwd)
}

func (this *Wallet) GetAccountCount() int {
	this.lock.RLock()
	defer this.lock.RUnlock()
	return len(this.accounts)
}

func (this *Wallet) GetDefaultAccountData() (*AccountData, error) {
	this.lock.RLock()
	defer this.lock.RUnlock()
	if this.defAcc == nil {
		return nil, fmt.Errorf("does not set default account")
	}
	return this.defAcc.Clone(), nil
}

func (this *Wallet) GetAccountDataByAddress(address string) (*AccountData, error) {
	this.lock.RLock()
	defer this.lock.RUnlock()
	accData, ok := this.accAddressMap[address]
	if !ok {
		return nil, ERR_ACCOUNT_NOT_FOUND
	}
	return accData.Clone(), nil
}

func (this *Wallet) GetAccountDataByLabel(label string) (*AccountData, error) {
	if label == "" {
		return nil, fmt.Errorf("cannot found account by empty label")
	}
	accData, ok := this.accLabelMap[label]
	if !ok {
		return nil, ERR_ACCOUNT_NOT_FOUND
	}
	return accData.Clone(), nil
}

//Index start from 1
func (this *Wallet) GetAccountDataByIndex(index int) (*AccountData, error) {
	this.lock.RLock()
	defer this.lock.RUnlock()
	if index <= 0 || index > len(this.accounts) {
		return nil, fmt.Errorf("index out of range")
	}
	accData := this.accounts[index-1]
	return accData.Clone(), nil
}

func (this *Wallet) SetLabel(address, newLabel string) error {
	this.lock.Lock()
	defer this.lock.Unlock()
	accData, ok := this.accAddressMap[address]
	if !ok {
		return ERR_ACCOUNT_NOT_FOUND
	}
	if accData.Label == newLabel {
		return nil
	}
	if newLabel == "" {
		delete(this.accLabelMap, accData.Label)
		accData.Label = ""
		return nil
	}
	_, ok = this.accLabelMap[newLabel]
	if ok {
		return fmt.Errorf("duplicate label")
	}
	accData.Label = newLabel
	this.accLabelMap[newLabel] = accData
	return nil
}

func (this *Wallet) SetSigScheme(address string, sigScheme s.SignatureScheme) error {
	this.lock.Lock()
	defer this.lock.Unlock()
	accData, ok := this.accAddressMap[address]
	if !ok {
		return ERR_ACCOUNT_NOT_FOUND
	}
	pubKeyData, err := hex.DecodeString(accData.PubKey)
	if err != nil {
		return err
	}
	pubKey, err := keypair.DeserializePublicKey(pubKeyData)
	if err != nil {
		return err
	}
	keyType := keypair.GetKeyType(pubKey)
	if CheckSigScheme(keyType, sigScheme) {
		return fmt.Errorf("sigScheme:%s does not match with KeyType:%s", sigScheme.Name(), accData.Alg)
	}
	accData.SigSch = sigScheme.Name()
	return nil
}

func (this *Wallet) ChangeAccountPassword(address string, oldPassword, newPassword []byte) error {
	this.lock.Lock()
	defer this.lock.Unlock()
	accData, ok := this.accAddressMap[address]
	if !ok {
		return ERR_ACCOUNT_NOT_FOUND
	}
	protectedKey, err := keypair.ReencryptPrivateKey(&accData.ProtectedKey, oldPassword, newPassword, this.Scrypt, this.Scrypt)
	if err != nil {
		return err
	}
	accData.SetKeyPair(protectedKey)
	return nil
}

func (this *Wallet) ImportAccounts(accountDatas []*AccountData, passwds [][]byte) error {
	if len(accountDatas) != len(passwds) {
		return fmt.Errorf("account size doesnot math password size")
	}
	for i := 0; i < len(accountDatas); i++ {
		accData := accountDatas[i]
		protectedkey, err := keypair.ReencryptPrivateKey(&accData.ProtectedKey, passwds[i], passwds[i], accData.GetScrypt(), this.Scrypt)
		if err != nil {
			return fmt.Errorf("ReencryptPrivateKey address:%s error:%s", accData.Address, err)
		}
		newAccData := &AccountData{
			PubKey:    accData.PubKey,
			SigSch:    accData.SigSch,
			Lock:      accData.Lock,
			IsDefault: false,
			Label:     accData.Label,
		}
		newAccData.SetKeyPair(protectedkey)
		_, err = this.GetAccountDataByLabel(accData.Label)
		if err != nil {
			//duplicate label, rename
			newAccData.Label = fmt.Sprintf("%s_1", accData.Label)
		}
		err = this.AddAccountData(newAccData)
		if err != nil {
			return fmt.Errorf("import account:%s, error:%s", accData.Address, err)
		}
	}
	return nil
}

func (this *Wallet) ExportAccounts(path string, accountDatas []*AccountData, passwds [][]byte, newScrypts ...*keypair.ScryptParam) (*Wallet, error) {
	var newScrypt keypair.ScryptParam
	if len(newScrypts) == 0 {
		newScrypt = *this.Scrypt
	} else {
		newScrypt = *newScrypts[0]
	}
	if len(accountDatas) != len(passwds) {
		return nil, fmt.Errorf("account size doesnot math password size")
	}
	newWallet := NewWallet(path)
	newWallet.Scrypt = &newScrypt
	for i := 0; i < len(accountDatas); i++ {
		accData := accountDatas[i]
		protectedkey, err := keypair.ReencryptPrivateKey(&accData.ProtectedKey, passwds[i], passwds[i], this.Scrypt, &newScrypt)
		if err != nil {
			return nil, fmt.Errorf("ReencryptPrivateKey address:%s error:%s", accData.Address, err)
		}
		newAccData := &AccountData{
			PubKey:    accData.PubKey,
			SigSch:    accData.SigSch,
			Lock:      accData.Lock,
			IsDefault: false,
			Label:     accData.Label,
		}
		newAccData.SetKeyPair(protectedkey)
		err = newWallet.AddAccountData(newAccData)
		if err != nil {
			return nil, fmt.Errorf("export account:%s error:%s", accData.Address, err)
		}
	}
	return newWallet, nil
}

func (this *Wallet) NewIdentity(keyType keypair.KeyType, curveCode byte, sigScheme s.SignatureScheme, passwd []byte) (*Identity, error) {
	identity, err := NewIdentity(this.Scrypt)
	if err != nil {
		return nil, err
	}
	//Key Index start from 1
	controllerId := "1"
	controllerData, err := NewControllerData(controllerId, keyType, curveCode, sigScheme, passwd, this.Scrypt)
	if err != nil {
		return nil, err
	}
	err = identity.AddControllerData(controllerData)
	if err != nil {
		return nil, err
	}
	err = this.AddIdentity(identity)
	if err != nil {
		return nil, err
	}
	return identity, nil
}

func (this *Wallet) NewDefaultSettingIdentity(passwd []byte) (*Identity, error) {
	return this.NewIdentity(keypair.PK_ECDSA, keypair.P256, s.SHA256withECDSA, passwd)
}

func (this *Wallet) GetDefaultIdentity() (*Identity, error) {
	this.lock.RLock()
	defer this.lock.RUnlock()
	if this.defIdentity == nil {
		return nil, fmt.Errorf("not set default identity")
	}
	return this.defIdentity, nil
}

func (this *Wallet) SetDefaultIdentity(id string) error {
	this.lock.Lock()
	defer this.lock.Unlock()
	identity, ok := this.identityMap[id]
	if !ok {
		return ERR_IDENTITY_NOT_FOUND
	}
	if this.defIdentity != nil {
		this.defIdentity.IsDefault = false
	}
	identity.IsDefault = true
	this.defIdentity = identity
	return nil
}

func (this *Wallet) AddIdentity(identity *Identity) error {
	this.lock.Lock()
	defer this.lock.Unlock()
	if this.defIdentity != nil && identity.IsDefault {
		return fmt.Errorf("already have default identity")
	}
	if this.defIdentity == nil {
		this.defIdentity = identity
		identity.IsDefault = true
	}
	this.identities = append(this.identities, identity)
	this.identityMap[identity.ID] = identity
	return nil
}

func (this *Wallet) DeleteIdentity(id string) error {
	this.lock.Lock()
	defer this.lock.Unlock()
	identity, ok := this.identityMap[id]
	if !ok {
		return ERR_IDENTITY_NOT_FOUND
	}
	if this.defIdentity.ID == id {
		return fmt.Errorf("cannot delete default identity")
	}
	delete(this.identityMap, id)
	if identity.Label != "" {
		delete(this.identityLabelMap, identity.Label)
	}
	size := len(this.identities)
	for index, ontId := range this.identities {
		if ontId.ID != id {
			continue
		}
		if size-1 == index {
			this.identities = this.identities[:index]
		} else {
			this.identities = append(this.identities[:index], this.identities[index+1:]...)
		}
		break
	}
	return nil
}

func (this *Wallet) GetIdentityById(id string) (*Identity, error) {
	this.lock.RLock()
	defer this.lock.RUnlock()
	identity, ok := this.identityMap[id]
	if !ok {
		return nil, ERR_IDENTITY_NOT_FOUND
	}
	return identity, nil
}

func (this *Wallet) GetIdentityByLabel(label string) (*Identity, error) {
	this.lock.RLock()
	defer this.lock.RUnlock()
	identity, ok := this.identityLabelMap[label]
	if !ok {
		return nil, ERR_IDENTITY_NOT_FOUND
	}
	return identity, nil
}

//Index start from 1
func (this *Wallet) GetIdentityByIndex(index int) (*Identity, error) {
	this.lock.RLock()
	defer this.lock.RUnlock()
	if index <= 0 || index > len(this.identities) {
		return nil, fmt.Errorf("index out of range")
	}
	return this.identities[index-1], nil
}

func (this *Wallet) SetIdentityLabel(id, newLabel string) error {
	this.lock.Lock()
	defer this.lock.Unlock()
	identity, ok := this.identityMap[id]
	if !ok {
		return ERR_IDENTITY_NOT_FOUND
	}
	if identity.Label == newLabel {
		return nil
	}
	if newLabel == "" {
		delete(this.identityLabelMap, identity.Label)
		identity.Label = ""
		return nil
	}
	_, ok = this.identityLabelMap[newLabel]
	if ok {
		return fmt.Errorf("duplicate label")
	}
	identity.Label = newLabel
	this.identityLabelMap[newLabel] = identity
	return nil
}

func (this *Wallet) GetIdentityCount() int {
	this.lock.RLock()
	defer this.lock.RUnlock()
	return len(this.identities)
}

func (this *Wallet) Save() error {
	this.lock.RLock()
	walletData := &WalletData{
		Name:       this.Name,
		Version:    this.Version,
		Scrypt:     this.Scrypt,
		Identities: make([]*IdentityData, 0),
		Accounts:   make([]*AccountData, 0),
		Extra:      this.Extra,
	}
	for _, identity := range this.identities {
		walletData.Identities = append(walletData.Identities, identity.ToIdentityData())
	}
	for _, acc := range this.accounts {
		walletData.Accounts = append(walletData.Accounts, acc)
	}
	this.lock.RUnlock()
	return walletData.Save(this.path)
}

type WalletData struct {
	Name       string               `json:"name"`
	Version    string               `json:"version"`
	Scrypt     *keypair.ScryptParam `json:"scrypt"`
	Identities []*IdentityData      `json:"identities,omitempty"`
	Accounts   []*AccountData       `json:"accounts,omitempty"`
	Extra      string               `json:"extra,omitempty"`
}

func NewWalletData() *WalletData {
	return &WalletData{
		Name:       "MyWallet",
		Version:    "1.1",
		Scrypt:     keypair.GetScryptParameters(),
		Identities: nil,
		Extra:      "",
		Accounts:   make([]*AccountData, 0, 0),
	}
}

func (this *WalletData) Clone() *WalletData {
	w := WalletData{}
	w.Name = this.Name
	w.Version = this.Version
	sp := *this.Scrypt
	w.Scrypt = &sp
	w.Accounts = make([]*AccountData, len(this.Accounts))
	for i, v := range this.Accounts {
		ac := *v
		ac.SetKeyPair(v.GetKeyPair())
		w.Accounts[i] = &ac
	}
	w.Identities = this.Identities
	w.Extra = this.Extra
	return &w
}

func (this *WalletData) Save(path string) error {
	data, err := json.Marshal(this)
	if err != nil {
		return err
	}
	if common.FileExisted(path) {
		filename := path + "~"
		err := ioutil.WriteFile(filename, data, 0644)
		if err != nil {
			return err
		}
		return os.Rename(filename, path)
	} else {
		return ioutil.WriteFile(path, data, 0644)
	}
}

func (this *WalletData) Load(path string) error {
	msh, err := ioutil.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(msh, this)
}

func ScryptEqual(s1, s2 *keypair.ScryptParam) bool {
	return s1.DKLen == s2.DKLen && s1.N == s2.N && s1.P == s2.P && s1.R == s2.R
}
