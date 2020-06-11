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
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	base58 "github.com/itchyny/base58-go"
	"github.com/ontio/ontology-crypto/keypair"
	s "github.com/ontio/ontology-crypto/signature"
	"github.com/ontio/ontology/core/types"
	"golang.org/x/crypto/ripemd160"
	"math/big"
)

const (
	SCHEME = "did"
	METHOD = "ont"
	VER    = 0x41
)

type Controller struct {
	ID         string
	PrivateKey keypair.PrivateKey
	PublicKey  keypair.PublicKey
	SigScheme  s.SignatureScheme
}

func (this *Controller) Sign(data []byte) ([]byte, error) {
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

func (this *Controller) GetPrivateKey() keypair.PrivateKey {
	return this.PrivateKey
}

func (this *Controller) GetPublicKey() keypair.PublicKey {
	return this.PublicKey
}

func (this *Controller) GetSigScheme() s.SignatureScheme {
	return this.SigScheme
}

type ControllerData struct {
	ID     string `json:"id"`
	Public string `json:"publicKey,omitemtpy"`
	SigSch string `json:"signatureScheme"`
	keypair.ProtectedKey
	scrypt *keypair.ScryptParam
}

func NewControllerData(id string, keyType keypair.KeyType, curveCode byte, sigScheme s.SignatureScheme, passwd []byte, scrypts ...*keypair.ScryptParam) (*ControllerData, error) {
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
	return NewControllerDataFromProtectedKey(id, hex.EncodeToString(keypair.SerializePublicKey(pubkey)), prvSecret, sigScheme.Name(), scrypt), nil
}

func NewControllerDataFromProtectedKey(id, pubKey string, protectedKey *keypair.ProtectedKey, SigSch string, scrypts ...*keypair.ScryptParam) *ControllerData {
	var scrypt *keypair.ScryptParam
	if len(scrypts) > 0 {
		scrypt = scrypts[0]
	} else {
		scrypt = keypair.GetScryptParameters()
	}
	ctrData := &ControllerData{
		ID:     id,
		Public: pubKey,
		scrypt: scrypt,
		SigSch: SigSch,
	}
	ctrData.SetKeyPair(protectedKey)
	return ctrData
}

func (this *ControllerData) GetController(passwd []byte) (*Controller, error) {
	privateKey, err := keypair.DecryptWithCustomScrypt(&this.ProtectedKey, passwd, this.scrypt)
	if err != nil {
		return nil, fmt.Errorf("decrypt privateKey error:%s", err)
	}
	publicKey := privateKey.Public()
	scheme, err := s.GetScheme(this.SigSch)
	if err != nil {
		return nil, fmt.Errorf("signature scheme error:%s", err)
	}
	return &Controller{
		ID:         this.ID,
		PrivateKey: privateKey,
		PublicKey:  publicKey,
		SigScheme:  scheme,
	}, nil
}

func (this *ControllerData) SetKeyPair(keyinfo *keypair.ProtectedKey) {
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

func (this *ControllerData) GetKeyPair() *keypair.ProtectedKey {
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

func (this *ControllerData) Clone() *ControllerData {
	ctrData := &ControllerData{
		ID:     this.ID,
		Public: this.Public,
		scrypt: this.scrypt,
		SigSch: this.SigSch,
	}
	ctrData.SetKeyPair(this.GetKeyPair())
	return ctrData
}

func (this *ControllerData) GetScrypt() *keypair.ScryptParam {
	return this.scrypt
}

type Identity struct {
	ID          string
	Label       string
	Lock        bool
	IsDefault   bool
	controllers []*ControllerData
	ctrsIdMap   map[string]*ControllerData
	ctrsPubMap  map[string]*ControllerData
	Extra       interface{}
	scrypt      *keypair.ScryptParam
}

func NewIdentity(scrypt *keypair.ScryptParam) (*Identity, error) {
	id, err := GenerateID()
	if err != nil {
		return nil, err
	}
	identity := &Identity{
		ID:          id,
		scrypt:      scrypt,
		controllers: make([]*ControllerData, 0),
		ctrsIdMap:   make(map[string]*ControllerData),
		ctrsPubMap:  make(map[string]*ControllerData),
	}
	return identity, nil
}

func NewIdentityFromIdentityData(identityData *IdentityData) (*Identity, error) {
	identity := &Identity{
		ID:          identityData.ID,
		Label:       identityData.Label,
		Lock:        identityData.Lock,
		IsDefault:   identityData.IsDefault,
		controllers: make([]*ControllerData, 0, len(identityData.Control)),
		ctrsIdMap:   make(map[string]*ControllerData),
		ctrsPubMap:  make(map[string]*ControllerData),
		scrypt:      identityData.scrypt,
	}
	for _, ctrData := range identityData.Control {
		if ctrData.scrypt == nil {
			ctrData.scrypt = identityData.scrypt
		}
		_, ok := identity.ctrsIdMap[ctrData.ID]
		if ok {
			return nil, fmt.Errorf("duplicate controller id:%s", ctrData.ID)
		}
		_, ok = identity.ctrsPubMap[ctrData.Public]
		if ok {
			return nil, fmt.Errorf("duplicate controller pubkey:%s", ctrData.Public)
		}
		identity.ctrsIdMap[ctrData.ID] = ctrData
		identity.ctrsPubMap[ctrData.Public] = ctrData
		identity.controllers = append(identity.controllers, ctrData)
	}
	return identity, nil
}

func (this *Identity) NewController(id string, keyType keypair.KeyType, curveCode byte, sigScheme s.SignatureScheme, passwd []byte) (*Controller, error) {
	controllerData, err := NewControllerData(id, keyType, curveCode, sigScheme, passwd)
	if err != nil {
		return nil, err
	}
	err = this.AddControllerData(controllerData)
	if err != nil {
		return nil, err
	}
	return controllerData.GetController(passwd)
}

func (this *Identity) NewDefaultSettingController(id string, passwd []byte) (*Controller, error) {
	return this.NewController(id, keypair.PK_ECDSA, keypair.P256, s.SHA256withECDSA, passwd)
}

func (this *Identity) AddControllerData(controllerData *ControllerData) error {
	if !ScryptEqual(controllerData.scrypt, this.scrypt) {
		return fmt.Errorf("scrypt unmatch")
	}
	if controllerData.ID == "" {
		return fmt.Errorf("controller id cannot empty string")
	}
	_, ok := this.ctrsIdMap[controllerData.ID]
	if ok {
		return fmt.Errorf("duplicate controller id:%s", controllerData.ID)
	}
	_, ok = this.ctrsPubMap[controllerData.Public]
	if ok {
		return fmt.Errorf("duplicate controller pubkey:%s", controllerData.Public)
	}
	this.controllers = append(this.controllers, controllerData)
	this.ctrsIdMap[controllerData.ID] = controllerData
	this.ctrsPubMap[controllerData.Public] = controllerData
	return nil
}

func (this *Identity) DeleteControllerData(id string) error {
	ctrData, ok := this.ctrsIdMap[id]
	if !ok {
		return ERR_CONTROLLER_NOT_FOUND
	}
	size := len(this.controllers)
	for index, ctrData := range this.controllers {
		if ctrData.ID != id {
			continue
		}
		if size-1 == index {
			this.controllers = this.controllers[:index]
		} else {
			this.controllers = append(this.controllers[:index], this.controllers[index+1:]...)
		}
	}
	delete(this.ctrsIdMap, id)
	delete(this.ctrsPubMap, ctrData.Public)
	return nil
}

func (this *Identity) GetControllerDataById(id string) (*ControllerData, error) {
	ctrData, ok := this.ctrsIdMap[id]
	if !ok {
		return nil, ERR_CONTROLLER_NOT_FOUND
	}
	return ctrData.Clone(), nil
}

func (this *Identity) GetControllerDataByPubKey(pubKey string) (*ControllerData, error) {
	ctrData, ok := this.ctrsPubMap[pubKey]
	if !ok {
		return nil, ERR_CONTROLLER_NOT_FOUND
	}
	return ctrData.Clone(), nil
}

func (this *Identity) GetControllerDataByIndex(index int) (*ControllerData, error) {
	if index <= 0 || index > len(this.controllers) {
		return nil, fmt.Errorf("index out of range")
	}
	return this.controllers[index-1].Clone(), nil
}

func (this *Identity) ControllerCount() int {
	return len(this.controllers)
}

func (this *Identity) GetControllerById(id string, passwd []byte) (*Controller, error) {
	ctrData, err := this.GetControllerDataById(id)
	if err != nil {
		return nil, err
	}
	return ctrData.GetController(passwd)
}

func (this *Identity) GetControllerByPubKey(pubKey string, passwd []byte) (*Controller, error) {
	ctrData, err := this.GetControllerDataByPubKey(pubKey)
	if err != nil {
		return nil, err
	}
	return ctrData.GetController(passwd)
}

func (this *Identity) GetControllerByIndex(index int, passwd []byte) (*Controller, error) {
	ctrData, err := this.GetControllerDataByIndex(index)
	if err != nil {
		return nil, err
	}
	return ctrData.GetController(passwd)
}

func (this *Identity) ToIdentityData() *IdentityData {
	identityData := &IdentityData{
		ID:      this.ID,
		Label:   this.Label,
		Lock:    this.Lock,
		Extra:   this.Extra,
		Control: make([]*ControllerData, 0, len(this.controllers)),
	}
	for _, ctr := range this.controllers {
		identityData.Control = append(identityData.Control, ctr.Clone())
	}
	return identityData
}

type IdentityData struct {
	ID        string            `json:"ontid"`
	Label     string            `json:"label,omitempty"`
	Lock      bool              `json:"lock"`
	IsDefault bool              `json:"isDefault"`
	Control   []*ControllerData `json:"controls,omitempty"`
	Extra     interface{}       `json:"extra,omitempty"`
	scrypt    *keypair.ScryptParam
}

func GenerateID() (string, error) {
	var buf [32]byte
	_, err := rand.Read(buf[:])
	if err != nil {
		return "", fmt.Errorf("generate ID error, %s", err)
	}
	return CreateID(buf[:])
}

func CreateID(nonce []byte) (string, error) {
	hasher := ripemd160.New()
	_, err := hasher.Write(nonce)
	if err != nil {
		return "", fmt.Errorf("create ID error, %s", err)
	}
	data := hasher.Sum([]byte{VER})
	data = append(data, checksum(data)...)

	bi := new(big.Int).SetBytes(data).String()
	idstring, err := base58.BitcoinEncoding.Encode([]byte(bi))
	if err != nil {
		return "", fmt.Errorf("create ID error, %s", err)
	}

	return SCHEME + ":" + METHOD + ":" + string(idstring), nil
}

func VerifyID(id string) bool {
	if len(id) < 9 {
		return false
	}
	if id[0:8] != "did:ont:" {
		return false
	}
	buf, err := base58.BitcoinEncoding.Decode([]byte(id[8:]))
	if err != nil {
		return false
	}
	bi, ok := new(big.Int).SetString(string(buf), 10)
	if !ok || bi == nil {
		return false
	}
	buf = bi.Bytes()
	// 1 byte version + 20 byte hash + 4 byte checksum
	if len(buf) != 25 {
		return false
	}
	pos := len(buf) - 4
	data := buf[:pos]
	check := buf[pos:]
	sum := checksum(data)
	if !bytes.Equal(sum, check) {
		return false
	}
	return true
}

func checksum(data []byte) []byte {
	sum := sha256.Sum256(data)
	sum = sha256.Sum256(sum[:])
	return sum[:4]
}

const (
	KEY_STATUS_REVOKE = "revoked"
	KEY_STSTUS_IN_USE = "in use"
)

type DDOOwner struct {
	pubKeyIndex uint32
	PubKeyId    string
	Type        string
	Curve       string
	Value       string
}

func (this *DDOOwner) GetIndex() uint32 {
	return this.pubKeyIndex
}

type DDOAttribute struct {
	Key       []byte
	Value     []byte
	ValueType []byte
}

type DDO struct {
	OntId      string
	Owners     []*DDOOwner
	Attributes []*DDOAttribute
	Recovery   string
}
