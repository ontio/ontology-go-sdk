/*
 * Copyright (C) 2018 The ontology Authors
 * This file is part of The ontology library.
 *
 * The ontology is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * The ontology is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with The ontology.  If not, see <http://www.gnu.org/licenses/>.
 */
package ontology_go_sdk

import (
	"crypto/elliptic"
	"encoding/hex"
	"fmt"
	"github.com/ontio/ontology-crypto/ec"
	"github.com/ontio/ontology-crypto/keypair"
	s "github.com/ontio/ontology-crypto/signature"
	"github.com/ontio/ontology/account"
	"github.com/ontio/ontology/core/types"
)

type Signer interface {
	Sign(data []byte) ([]byte, error)
	GetPublicKey() keypair.PublicKey
	GetPrivateKey() keypair.PrivateKey
	GetSigScheme() s.SignatureScheme
}

type Account account.Account

func NewAccountFromPrivateKey(privateKey []byte, signatureScheme s.SignatureScheme) (*Account, error) {
	if privateKey == nil {
		return nil, fmt.Errorf("privatekey should not be nil")
	}
	if len(privateKey) != 32 {
		return nil, fmt.Errorf("the length of privatekey should be 32")
	}
	prikey := ec.ConstructPrivateKey(privateKey, elliptic.P256())
	privaKey := ec.PrivateKey{
		Algorithm:  ec.ECDSA,
		PrivateKey: prikey,
	}
	address := types.AddressFromPubKey(privaKey.Public())
	return &Account{
		PrivateKey: &privaKey,
		PublicKey:  privaKey.Public(),
		Address:    address,
		SigScheme:  signatureScheme,
	}, nil
}
func NewAccount(sigscheme ...s.SignatureScheme) *Account {
	var scheme s.SignatureScheme
	if len(sigscheme) == 0 {
		scheme = s.SHA256withECDSA
	} else {
		scheme = sigscheme[0]
	}
	var pkAlgorithm keypair.KeyType
	var params interface{}
	switch scheme {
	case s.SHA224withECDSA, s.SHA3_224withECDSA:
		pkAlgorithm = keypair.PK_ECDSA
		params = keypair.P224
	case s.SHA256withECDSA, s.SHA3_256withECDSA, s.RIPEMD160withECDSA:
		pkAlgorithm = keypair.PK_ECDSA
		params = keypair.P256
	case s.SHA384withECDSA, s.SHA3_384withECDSA:
		pkAlgorithm = keypair.PK_ECDSA
		params = keypair.P384
	case s.SHA512withECDSA, s.SHA3_512withECDSA:
		pkAlgorithm = keypair.PK_ECDSA
		params = keypair.P521
	case s.SM3withSM2:
		pkAlgorithm = keypair.PK_SM2
		params = keypair.SM2P256V1
	case s.SHA512withEDDSA:
		pkAlgorithm = keypair.PK_EDDSA
		params = keypair.ED25519
	default:
		return nil
	}
	pri, pub, _ := keypair.GenerateKeyPair(pkAlgorithm, params)
	address := types.AddressFromPubKey(pub)
	return &Account{
		PrivateKey: pri,
		PublicKey:  pub,
		Address:    address,
		SigScheme:  scheme,
	}
}

func (this *Account) Sign(data []byte) ([]byte, error) {
	sig, err := s.Sign(this.SigScheme, this.PrivateKey, data, nil)
	if err != nil {
		return nil, err
	}
	sigData, err := s.Serialize(sig)
	if err != nil {
		return nil, fmt.Errorf("signature.Serialize error:%s", err)
	}
	return sigData, nil
}

func (this *Account) GetPrivateKey() keypair.PrivateKey {
	return this.PrivateKey
}

func (this *Account) GetPublicKey() keypair.PublicKey {
	return this.PublicKey
}

func (this *Account) GetSigScheme() s.SignatureScheme {
	return this.SigScheme
}

/** AccountData - for wallet read and save, no crypto object included **/
type AccountData struct {
	keypair.ProtectedKey

	Label     string `json:"label"`
	PubKey    string `json:"publicKey"`
	SigSch    string `json:"signatureScheme"`
	IsDefault bool   `json:"isDefault"`
	Lock      bool   `json:"lock"`
	scrypt    *keypair.ScryptParam
}

func NewAccountData(keyType keypair.KeyType, curveCode byte, sigScheme s.SignatureScheme, passwd []byte, scrypts ...*keypair.ScryptParam) (*AccountData, error) {
	if len(passwd) == 0 {
		return nil, fmt.Errorf("password cannot empty")
	}
	if !CheckKeyTypeCurve(keyType, curveCode) {
		return nil, fmt.Errorf("curve unmath key type")
	}
	if !CheckSigScheme(keyType, sigScheme) {
		return nil, fmt.Errorf("sigScheme:%s does not match with KeyType:%s", sigScheme.Name(), GetKeyTypeString(keyType))
	}
	var scrypt *keypair.ScryptParam
	if len(scrypts) > 0 {
		scrypt = scrypts[0]
	} else {
		scrypt = keypair.GetScryptParameters()
	}
	prvkey, pubkey, err := keypair.GenerateKeyPair(keyType, curveCode)
	if err != nil {
		return nil, fmt.Errorf("generateKeyPair error:%s", err)
	}
	address := types.AddressFromPubKey(pubkey)
	addressBase58 := address.ToBase58()
	prvSecret, err := keypair.EncryptWithCustomScrypt(prvkey, addressBase58, passwd, scrypt)
	if err != nil {
		return nil, fmt.Errorf("encryptPrivateKey error:%s", err)
	}
	accData := &AccountData{}
	accData.SetKeyPair(prvSecret)
	accData.SigSch = sigScheme.Name()
	accData.PubKey = hex.EncodeToString(keypair.SerializePublicKey(pubkey))
	accData.scrypt = scrypt
	return accData, nil
}

func (this *AccountData) GetAccount(passwd []byte) (*Account, error) {
	privateKey, err := keypair.DecryptWithCustomScrypt(&this.ProtectedKey, passwd, this.scrypt)
	if err != nil {
		return nil, fmt.Errorf("decrypt privateKey error:%s", err)
	}
	publicKey := privateKey.Public()
	addr := types.AddressFromPubKey(publicKey)
	scheme, err := s.GetScheme(this.SigSch)
	if err != nil {
		return nil, fmt.Errorf("signature scheme error:%s", err)
	}
	return &Account{
		PrivateKey: privateKey,
		PublicKey:  publicKey,
		Address:    addr,
		SigScheme:  scheme,
	}, nil
}

func (this *AccountData) GetScrypt() *keypair.ScryptParam {
	return this.scrypt
}
func (this *AccountData) SetScript(scrypt *keypair.ScryptParam) {
	this.scrypt = scrypt
}

func (this *AccountData) Clone() *AccountData {
	accData := &AccountData{
		Label:     this.Label,
		PubKey:    this.PubKey,
		SigSch:    this.SigSch,
		IsDefault: this.IsDefault,
		Lock:      this.Lock,
		scrypt:    this.scrypt,
	}
	accData.SetKeyPair(this.GetKeyPair())
	return accData
}

func (this *AccountData) SetKeyPair(keyinfo *keypair.ProtectedKey) {
	this.Address = keyinfo.Address
	this.EncAlg = keyinfo.EncAlg
	this.Alg = keyinfo.Alg
	this.Hash = keyinfo.Hash
	this.Key = make([]byte, len(keyinfo.Key))
	copy(this.Key, keyinfo.Key)
	this.Param = keyinfo.Param
	this.Salt = make([]byte, len(keyinfo.Salt))
	copy(this.Salt, keyinfo.Salt)
}

func (this *AccountData) GetKeyPair() *keypair.ProtectedKey {
	var keyinfo = new(keypair.ProtectedKey)
	keyinfo.Address = this.Address
	keyinfo.EncAlg = this.EncAlg
	keyinfo.Alg = this.Alg
	keyinfo.Hash = this.Hash
	keyinfo.Key = make([]byte, len(this.Key))
	copy(keyinfo.Key, this.Key)
	keyinfo.Param = this.Param
	keyinfo.Salt = make([]byte, len(this.Salt))
	copy(keyinfo.Salt, this.Salt)
	return keyinfo
}

func GetKeyTypeString(keyType keypair.KeyType) string {
	switch keyType {
	case keypair.PK_ECDSA:
		return "ECDSA"
	case keypair.PK_SM2:
		return "SM2"
	case keypair.PK_EDDSA:
		return "Ed25519"
	default:
		return "unknown key type"
	}
}

func CheckKeyTypeCurve(keyType keypair.KeyType, curveCode byte) bool {
	switch keyType {
	case keypair.PK_ECDSA:
		switch curveCode {
		case keypair.P224:
		case keypair.P256:
		case keypair.P384:
		case keypair.P521:
		default:
			return false
		}
	case keypair.PK_SM2:
		switch curveCode {
		case keypair.SM2P256V1:
		default:
			return false
		}
	case keypair.PK_EDDSA:
		switch curveCode {
		case keypair.ED25519:
		default:
			return false
		}
	}
	return true
}

func CheckSigScheme(keyType keypair.KeyType, sigScheme s.SignatureScheme) bool {
	switch keyType {
	case keypair.PK_ECDSA:
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
	case keypair.PK_SM2:
		switch sigScheme {
		case s.SM3withSM2:
		default:
			return false
		}
	case keypair.PK_EDDSA:
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

func GetCurveName(pubKey []byte) string {
	if len(pubKey) < 2 {
		return ""
	}
	switch keypair.KeyType(pubKey[0]) {
	case keypair.PK_ECDSA, keypair.PK_SM2:
		c, err := keypair.GetCurve(pubKey[1])
		if err != nil {
			return ""
		}
		return c.Params().Name
	case keypair.PK_EDDSA:
		if pubKey[1] == keypair.ED25519 {
			return "ed25519"
		} else {
			return ""
		}
	default:
		return ""
	}
}
