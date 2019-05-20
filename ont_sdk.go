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

//Ontolog sdk in golang. Using for operation with ontology
package ontology_go_sdk

import (
	"encoding/hex"
	"fmt"
	"github.com/ontio/go-bip32"
	"github.com/ontio/ontology-go-sdk/bip44"
	"github.com/ontio/ontology/smartcontract/event"
	"github.com/tyler-smith/go-bip39"
	"math/rand"
	"time"

	"github.com/ontio/ontology-crypto/keypair"
	"github.com/ontio/ontology-go-sdk/client"
	"github.com/ontio/ontology-go-sdk/utils"
	"github.com/ontio/ontology/common"
	sign "github.com/ontio/ontology/common"
	"github.com/ontio/ontology/common/constants"
	"github.com/ontio/ontology/core/payload"
	"github.com/ontio/ontology/core/types"
)

func init() {
	rand.Seed(time.Now().UnixNano())
}

//OntologySdk is the main struct for user
type OntologySdk struct {
	client.ClientMgr
	Native *NativeContract
	NeoVM  *NeoVMContract
}

//NewOntologySdk return OntologySdk.
func NewOntologySdk() *OntologySdk {
	ontSdk := &OntologySdk{}
	native := newNativeContract(ontSdk)
	ontSdk.Native = native
	neoVM := newNeoVMContract(ontSdk)
	ontSdk.NeoVM = neoVM
	return ontSdk
}

//CreateWallet return a new wallet
func (this *OntologySdk) CreateWallet(walletFile string) (*Wallet, error) {
	if utils.IsFileExist(walletFile) {
		return nil, fmt.Errorf("wallet:%s has already exist", walletFile)
	}
	return NewWallet(walletFile), nil
}

//OpenWallet return a wallet instance
func (this *OntologySdk) OpenWallet(walletFile string) (*Wallet, error) {
	return OpenWallet(walletFile)
}

func (this *OntologySdk) GenerateMnemonicCodesStr() (string, error) {
	entropy, err := bip39.NewEntropy(128)
	if err != nil {
		return "", err
	}
	return bip39.NewMnemonic(entropy)
}

func (this *OntologySdk) GetPrivateKeyFromMnemonicCodesStrBip44(mnemonicCodesStr string, index uint32) ([]byte, error) {
	if mnemonicCodesStr == "" {
		return nil, fmt.Errorf("mnemonicCodesStr should not be nil")
	}
	//address_index
	if index < 0 {
		return nil, fmt.Errorf("index should be bigger than 0")
	}
	seed := bip39.NewSeed(mnemonicCodesStr, "")
	masterKey, err := bip32.NewMasterKey(seed)
	if err != nil {
		return nil, err
	}
	//m / purpose' / coin_type' / account' / change / address_index
	//coin type 1024'
	coin := 0x80000400
	//account 0'
	account := 0x80000000
	key, err := bip44.NewKeyFromMasterKey(masterKey, uint32(coin), uint32(account), 0, index)
	if err != nil {
		return nil, err
	}
	keyBytes, err := key.Serialize()
	if err != nil {
		return nil, err
	}
	return keyBytes[46:78], nil
}

//NewInvokeTransaction return smart contract invoke transaction
func (this *OntologySdk) NewInvokeTransaction(gasPrice, gasLimit uint64, invokeCode []byte) *types.MutableTransaction {
	invokePayload := &payload.InvokeCode{
		Code: invokeCode,
	}
	tx := &types.MutableTransaction{
		GasPrice: gasPrice,
		GasLimit: gasLimit,
		TxType:   types.Invoke,
		Nonce:    rand.Uint32(),
		Payload:  invokePayload,
		Sigs:     make([]types.Sig, 0, 0),
	}
	return tx
}

func (this *OntologySdk) SignToTransaction(tx *types.MutableTransaction, signer Signer) error {
	if tx.Payer == common.ADDRESS_EMPTY {
		account, ok := signer.(*Account)
		if ok {
			tx.Payer = account.Address
		}
	}
	for _, sigs := range tx.Sigs {
		if utils.PubKeysEqual([]keypair.PublicKey{signer.GetPublicKey()}, sigs.PubKeys) {
			//have already signed
			return nil
		}
	}
	txHash := tx.Hash()
	sigData, err := signer.Sign(txHash.ToArray())
	if err != nil {
		return fmt.Errorf("sign error:%s", err)
	}
	if tx.Sigs == nil {
		tx.Sigs = make([]types.Sig, 0)
	}
	tx.Sigs = append(tx.Sigs, types.Sig{
		PubKeys: []keypair.PublicKey{signer.GetPublicKey()},
		M:       1,
		SigData: [][]byte{sigData},
	})
	return nil
}

func (this *OntologySdk) MultiSignToTransaction(tx *types.MutableTransaction, m uint16, pubKeys []keypair.PublicKey, signer Signer) error {
	pkSize := len(pubKeys)
	if m == 0 || int(m) > pkSize || pkSize > constants.MULTI_SIG_MAX_PUBKEY_SIZE {
		return fmt.Errorf("both m and number of pub key must larger than 0, and small than %d, and m must smaller than pub key number", constants.MULTI_SIG_MAX_PUBKEY_SIZE)
	}
	validPubKey := false
	for _, pk := range pubKeys {
		if keypair.ComparePublicKey(pk, signer.GetPublicKey()) {
			validPubKey = true
			break
		}
	}
	if !validPubKey {
		return fmt.Errorf("invalid signer")
	}
	if tx.Payer == common.ADDRESS_EMPTY {
		payer, err := types.AddressFromMultiPubKeys(pubKeys, int(m))
		if err != nil {
			return fmt.Errorf("AddressFromMultiPubKeys error:%s", err)
		}
		tx.Payer = payer
	}
	txHash := tx.Hash()
	if len(tx.Sigs) == 0 {
		tx.Sigs = make([]types.Sig, 0)
	}
	sigData, err := signer.Sign(txHash.ToArray())
	if err != nil {
		return fmt.Errorf("sign error:%s", err)
	}
	hasMutilSig := false
	for i, sigs := range tx.Sigs {
		if utils.PubKeysEqual(sigs.PubKeys, pubKeys) {
			hasMutilSig = true
			if utils.HasAlreadySig(txHash.ToArray(), signer.GetPublicKey(), sigs.SigData) {
				break
			}
			sigs.SigData = append(sigs.SigData, sigData)
			tx.Sigs[i] = sigs
			break
		}
	}
	if !hasMutilSig {
		tx.Sigs = append(tx.Sigs, types.Sig{
			PubKeys: pubKeys,
			M:       m,
			SigData: [][]byte{sigData},
		})
	}
	return nil
}

func (this *OntologySdk) GetTxData(tx *types.MutableTransaction) (string, error) {
	txData, err := tx.IntoImmutable()
	if err != nil {
		return "", fmt.Errorf("IntoImmutable error:%s", err)
	}
	sink := sign.ZeroCopySink{}
	txData.Serialization(&sink)
	rawtx := hex.EncodeToString(sink.Bytes())
	return rawtx, nil
}

type OEP4TransferEvent struct {
	FuncName string
	From     string
	To       string
	Amount   uint64
}

func (this *OntologySdk) ParseOEP4TransferEvent(event *event.NotifyEventInfo) (*OEP4TransferEvent, error) {
	if event == nil {
		return nil, fmt.Errorf("event is nil")
	}
	state, ok := event.States.([]interface{})
	if !ok {
		return nil, fmt.Errorf("state.States is not []interface")
	}
	if len(state) != 4 {
		return nil, fmt.Errorf("state length is not 4")
	}
	funcName, ok := state[0].(string)
	if !ok {
		return nil, fmt.Errorf("state.States[0] is not string")
	}
	if funcName != "transfer" {
		return nil, fmt.Errorf("funcName is not transfer")
	} else {
		from, ok := state[1].(string)
		if !ok {
			return nil, fmt.Errorf("state[1] is not string")
		}
		to, ok := state[2].(string)
		if !ok {
			return nil, fmt.Errorf("state[2] is not string")
		}
		amount, ok := state[3].(uint64)
		if !ok {
			return nil, fmt.Errorf("state[3] is not uint64")
		}
		return &OEP4TransferEvent{
			FuncName: "transfer",
			From:     from,
			To:       to,
			Amount:   uint64(amount),
		}, nil
	}
}

func (this *OntologySdk) GetMutableTx(rawTx string) (*types.MutableTransaction, error) {
	txData, err := hex.DecodeString(rawTx)
	if err != nil {
		return nil, fmt.Errorf("RawTx hex decode error:%s", err)
	}
	tx, err := types.TransactionFromRawBytes(txData)
	if err != nil {
		return nil, fmt.Errorf("TransactionFromRawBytes error:%s", err)
	}
	mutTx, err := tx.IntoMutable()
	if err != nil {
		return nil, fmt.Errorf("[ONT]IntoMutable error:%s", err)
	}
	return mutTx, nil
}

func (this *OntologySdk) GetMultiAddr(pubkeys []keypair.PublicKey, m int) (string, error) {
	addr, err := types.AddressFromMultiPubKeys(pubkeys, m)
	if err != nil {
		return "", fmt.Errorf("GetMultiAddrs error:%s", err)
	}
	return addr.ToBase58(), nil
}

func (this *OntologySdk) GetAdddrByPubKey(pubKey keypair.PublicKey) string {
	address := types.AddressFromPubKey(pubKey)
	return address.ToBase58()
}
