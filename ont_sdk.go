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
	"io"
	"math/rand"
	"time"

	"github.com/ontio/ontology-crypto/keypair"
	"github.com/ontio/ontology-go-sdk/client"
	common3 "github.com/ontio/ontology-go-sdk/common"
	"github.com/ontio/ontology-go-sdk/utils"
	"github.com/ontio/ontology/common"
	common2 "github.com/ontio/ontology/common"
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
	WasmVM *WasmVMContract
}

//NewOntologySdk return OntologySdk.
func NewOntologySdk() *OntologySdk {
	ontSdk := &OntologySdk{}
	native := newNativeContract(ontSdk)
	ontSdk.Native = native
	neoVM := newNeoVMContract(ontSdk)
	ontSdk.NeoVM = neoVM
	wasmVM := newWasmVMContract(ontSdk)
	ontSdk.WasmVM = wasmVM
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

func ParseNativeTxPayload(raw []byte) (map[string]interface{}, error) {
	tx, err := types.TransactionFromRawBytes(raw)
	if err != nil {
		return nil, err
	}
	invokeCode, ok := tx.Payload.(*payload.InvokeCode)
	if !ok {
		return nil, fmt.Errorf("error payload")
	}
	code := invokeCode.Code
	return ParsePayload(code)
}

func ParsePayload(code []byte) (map[string]interface{}, error) {
	l := len(code)
	if l > 44 && string(code[l-22:]) == "Ontology.Native.Invoke" {
		//46 = 22  "Ontology.Native.Invoke"
		// +1   length
		// +1   SYSCALL
		// +1   version
		// +20  address
		// +1   length
		//TODO if version>15, there will be bug
		if l > 54 && string(code[l-46-8:l-46]) == "transfer" {
			param := make([]common3.StateInfo, 0)
			source := common.NewZeroCopySource(code)
			for {
				zeroByte, eof := source.NextByte()
				if eof {
					return nil, io.ErrUnexpectedEOF
				}
				if zeroByte != 0 {
					break
				}
				err := ignoreOpCode(source)
				if err != nil {
					return nil, err
				}
				from, err := readAddress(source)
				if err != nil {
					return nil, err
				}
				err = ignoreOpCode(source)
				if err != nil {
					return nil, err
				}
				to, err := readAddress(source)
				if err != nil {
					return nil, err
				}
				err = ignoreOpCode(source)
				if err != nil {
					return nil, err
				}
				amount, err := getValue(source)
				if err != nil {
					return nil, err
				}
				state := common3.StateInfo{
					From:  from.ToBase58(),
					To:    to.ToBase58(),
					Value: amount,
				}
				param = append(param, state)
				err = ignoreOpCode(source)
				if err != nil {
					return nil, err
				}
				var isend bool
				if isend, err = isEnd(source); err != nil {
					return nil, err
				}
				if isend {
					break
				}
			}
			err := ignoreOpCode(source)
			if err != nil {
				return nil, err
			}
			//method name
			_, _, irregular, eof := source.NextVarBytes()
			if irregular || eof {
				return nil, io.ErrUnexpectedEOF
			}
			//contract address
			contractAddress, err := readAddress(source)
			if err != nil {
				return nil, err
			}
			res := make(map[string]interface{})
			res["functionName"] = "transfer"
			res["contractAddress"] = contractAddress
			res["param"] = param
			if contractAddress == ONT_CONTRACT_ADDRESS {
				res["asset"] = "ont"
			} else if contractAddress == ONG_CONTRACT_ADDRESS {
				res["asset"] = "ong"
			}
			return res, nil
		} else if l > 58 && string(code[l-46-12:l-46]) == "transferFrom" {
			source := common.NewZeroCopySource(code)
			//ignore 00
			_, eof := source.NextByte()
			if eof {
				return nil, io.ErrUnexpectedEOF
			}
			err := ignoreOpCode(source)
			if err != nil {
				return nil, err
			}
			sender, err := readAddress(source)
			if err != nil {
				return nil, err
			}
			err = ignoreOpCode(source)
			if err != nil {
				return nil, err
			}
			from, err := readAddress(source)
			if err != nil {
				return nil, err
			}
			err = ignoreOpCode(source)
			if err != nil {
				return nil, err
			}
			to, err := readAddress(source)
			if err != nil {
				return nil, err
			}
			err = ignoreOpCode(source)
			if err != nil {
				return nil, err
			}
			amount, err := getValue(source)
			if err != nil {
				return nil, err
			}
			tf := common3.TransferFromInfo{
				Sender: sender.ToBase58(),
				From:   from.ToBase58(),
				To:     to.ToBase58(),
				Value:  amount,
			}
			err = ignoreOpCode(source)
			if err != nil {
				return nil, err
			}
			//method name
			_, _, irregular, eof := source.NextVarBytes()
			if irregular || eof {
				return nil, io.ErrUnexpectedEOF
			}
			//contract address
			contractAddress, err := readAddress(source)
			if err != nil {
				return nil, err
			}
			res := make(map[string]interface{})
			res["functionName"] = "transferFrom"
			res["contractAddress"] = contractAddress
			res["param"] = tf
			if contractAddress == ONT_CONTRACT_ADDRESS {
				res["asset"] = "ont"
			} else if contractAddress == ONG_CONTRACT_ADDRESS {
				res["asset"] = "ong"
			}
			return res, nil
		}
	}
	return nil, fmt.Errorf("not native transfer and transferFrom transaction")
}
func getValue(source *common.ZeroCopySource) (uint64, error) {
	var amount = uint64(0)
	zeroByte, eof := source.NextByte()
	if eof {
		return 0, io.ErrUnexpectedEOF
	}

	if zeroByte == 0 {
		amount = 0
	} else if zeroByte >= 0x51 && zeroByte <= 0x5f {
		b := common.BigIntFromNeoBytes([]byte{zeroByte})
		amount = b.Uint64() - 0x50
	} else {
		source.BackUp(1)
		amountBytes, _, irregular, eof := source.NextVarBytes()
		if irregular || eof {
			return 0, io.ErrUnexpectedEOF
		}
		amount = common.BigIntFromNeoBytes(amountBytes).Uint64()
	}
	return amount, nil
}
func isEnd(source *common.ZeroCopySource) (bool, error) {
	by, eof := source.NextByte()
	if eof {
		return true, io.EOF
	}
	if by == 0x00 || by >= 0x14 && by < 0x51 {
		source.BackUp(1)
		return false, nil
	} else {
		if by >= 0x51 && by <= 0x5f {
			return true, nil
		} else {
			_, _, irregular, eof := source.NextVarUint()
			if irregular || eof {
				return true, io.ErrUnexpectedEOF
			}
			return true, nil
		}
	}
}

func readAddress(source *common.ZeroCopySource) (common2.Address, error) {
	senderBytes, _, irregular, eof := source.NextVarBytes()
	if irregular || eof {
		return common.ADDRESS_EMPTY, io.ErrUnexpectedEOF
	}
	sender, err := utils.AddressParseFromBytes(senderBytes)
	if err != nil {
		return common.ADDRESS_EMPTY, err
	}
	return sender, nil
}
func ignoreOpCode(source *common.ZeroCopySource) error {
	s := source.Size()
	start := source.Pos()
	for {
		if source.Pos() >= s {
			return nil
		}
		by, eof := source.NextByte()
		if eof {
			return io.EOF
		}
		if OPCODE_IN_PAYLOAD[by] {
			continue
		} else {
			if start < source.Pos() {
				source.BackUp(1)
			}
			return nil
		}
	}
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
		TxType:   types.InvokeNeo,
		Nonce:    rand.Uint32(),
		Payload:  invokePayload,
		Sigs:     make([]types.Sig, 0, 0),
	}
	return tx
}

func (this *OntologySdk) SetPayer(tx *types.MutableTransaction, payer common.Address) {
	tx.Payer = payer
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
	sink := common2.ZeroCopySink{}
	txData.Serialization(&sink)
	rawtx := hex.EncodeToString(sink.Bytes())
	return rawtx, nil
}

type TransferEvent struct {
	FuncName string
	From     string
	To       string
	Amount   uint64
}

func (this *OntologySdk) ParseNaitveTransferEvent(event *event.NotifyEventInfo) (*TransferEvent, error) {
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
		return &TransferEvent{
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

func (this *OntologySdk) SendTransaction(tx *types.MutableTransaction) (common.Uint256, error) {
	return this.ClientMgr.SendTransaction(tx)
}
