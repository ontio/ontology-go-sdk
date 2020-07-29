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
	"encoding/hex"
	"fmt"
	"github.com/ontio/ontology-crypto/signature"
	common2 "github.com/ontio/ontology-go-sdk/common"
	sdk_utils "github.com/ontio/ontology-go-sdk/utils"
	"github.com/ontio/ontology/common"
	"github.com/ontio/ontology/core/payload"
	"github.com/ontio/ontology/core/utils"
	"github.com/ontio/ontology/core/validation"
	"github.com/ontio/ontology/smartcontract/event"
	"github.com/ontio/ontology/smartcontract/service/native/ont"
	"github.com/stretchr/testify/assert"
	"github.com/tyler-smith/go-bip39"
	"math/rand"
	"testing"
	"time"
)

var (
	testOntSdk   *OntologySdk
	testWallet   *Wallet
	testPasswd   = []byte("123456")
	testDefAcc   *Account
	testGasPrice = uint64(2500)
	testGasLimit = uint64(20000)
	testNetUrl   = "http://polaris2.ont.io:20336"
)

func init() {
	var err error
	testWallet, err = testOntSdk.OpenWallet("./wallet.dat")
	if err != nil {
		fmt.Printf("OpenWallet err: %s\n", err)
		return
	}
	testOntSdk = NewOntologySdk(sdk_utils.LAYER2_SDK)
	testOntSdk.NewRpcClient(sdk_utils.LAYER2_SDK).SetAddress(testNetUrl)
	testDefAcc, err = testWallet.GetDefaultAccount(testPasswd)
	if err != nil {
		fmt.Printf("GetDefaultAccount err: %s\n", err)
		return
	}
}
func TestOntId_NewRegIDWithAttributesTransaction(t *testing.T) {
	testOntSdk = NewOntologySdk(sdk_utils.LAYER2_SDK)
}
func TestParseNativeTxPayload(t *testing.T) {
	testOntSdk = NewOntologySdk(sdk_utils.LAYER2_SDK)
	pri, err := common.HexToBytes("75de8489fcb2dcaf2ef3cd607feffde18789de7da129b5e97c81e001793cb7cf")
	assert.Nil(t, err)
	acc, err := NewAccountFromPrivateKey(pri, signature.SHA256withECDSA)
	state := &ont.State{
		From:  acc.Address,
		To:    acc.Address,
		Value: uint64(100),
	}
	transfers := make([]*ont.State, 0)
	for i := 0; i < 1; i++ {
		transfers = append(transfers, state)
	}
	_, err = testOntSdk.Native.Ont.NewMultiTransferTransaction(2500, 20000, transfers)
	assert.Nil(t, err)
	_, err = testOntSdk.Native.Ont.NewTransferFromTransaction(2500, 20000, acc.Address, acc.Address, acc.Address, 20)
	assert.Nil(t, err)
}

func TestParsePayload(t *testing.T) {
	testOntSdk = NewOntologySdk(sdk_utils.LAYER2_SDK)
	//transferMulti
	payloadHex := "00c66b6a14d2c124dd088190f709b684e0bc676d70c41b3776c86a14d2c124dd088190f709b684e0bc676d70c41b3776c86a0164c86c00c66b6a14d2c124dd088190f709b684e0bc676d70c41b3776c86a14d2c124dd088190f709b684e0bc676d70c41b3776c86a0164c86c00c66b6a14d2c124dd088190f709b684e0bc676d70c41b3776c86a14d2c124dd088190f709b684e0bc676d70c41b3776c86a0164c86c00c66b6a14d2c124dd088190f709b684e0bc676d70c41b3776c86a14d2c124dd088190f709b684e0bc676d70c41b3776c86a0164c86c00c66b6a14d2c124dd088190f709b684e0bc676d70c41b3776c86a14d2c124dd088190f709b684e0bc676d70c41b3776c86a0164c86c00c66b6a14d2c124dd088190f709b684e0bc676d70c41b3776c86a14d2c124dd088190f709b684e0bc676d70c41b3776c86a0164c86c00c66b6a14d2c124dd088190f709b684e0bc676d70c41b3776c86a14d2c124dd088190f709b684e0bc676d70c41b3776c86a0164c86c00c66b6a14d2c124dd088190f709b684e0bc676d70c41b3776c86a14d2c124dd088190f709b684e0bc676d70c41b3776c86a0164c86c00c66b6a14d2c124dd088190f709b684e0bc676d70c41b3776c86a14d2c124dd088190f709b684e0bc676d70c41b3776c86a0164c86c00c66b6a14d2c124dd088190f709b684e0bc676d70c41b3776c86a14d2c124dd088190f709b684e0bc676d70c41b3776c86a0164c86c00c66b6a14d2c124dd088190f709b684e0bc676d70c41b3776c86a14d2c124dd088190f709b684e0bc676d70c41b3776c86a0164c86c00c66b6a14d2c124dd088190f709b684e0bc676d70c41b3776c86a14d2c124dd088190f709b684e0bc676d70c41b3776c86a0164c86c00c66b6a14d2c124dd088190f709b684e0bc676d70c41b3776c86a14d2c124dd088190f709b684e0bc676d70c41b3776c86a0164c86c00c66b6a14d2c124dd088190f709b684e0bc676d70c41b3776c86a14d2c124dd088190f709b684e0bc676d70c41b3776c86a0164c86c00c66b6a14d2c124dd088190f709b684e0bc676d70c41b3776c86a14d2c124dd088190f709b684e0bc676d70c41b3776c86a0164c86c00c66b6a14d2c124dd088190f709b684e0bc676d70c41b3776c86a14d2c124dd088190f709b684e0bc676d70c41b3776c86a0164c86c00c66b6a14d2c124dd088190f709b684e0bc676d70c41b3776c86a14d2c124dd088190f709b684e0bc676d70c41b3776c86a0164c86c00c66b6a14d2c124dd088190f709b684e0bc676d70c41b3776c86a14d2c124dd088190f709b684e0bc676d70c41b3776c86a0164c86c00c66b6a14d2c124dd088190f709b684e0bc676d70c41b3776c86a14d2c124dd088190f709b684e0bc676d70c41b3776c86a0164c86c00c66b6a14d2c124dd088190f709b684e0bc676d70c41b3776c86a14d2c124dd088190f709b684e0bc676d70c41b3776c86a0164c86c0114c1087472616e736665721400000000000000000000000000000000000000010068164f6e746f6c6f67792e4e61746976652e496e766f6b65"
	//one transfer
	payloadHex = "00c66b6a14d2c124dd088190f709b684e0bc676d70c41b3776c86a14d2c124dd088190f709b684e0bc676d70c41b3776c86a0164c86c51c1087472616e736665721400000000000000000000000000000000000000010068164f6e746f6c6f67792e4e61746976652e496e766f6b65"

	//one transferFrom
	payloadHex = "00c66b6a14d2c124dd088190f709b684e0bc676d70c41b3776c86a14d2c124dd088190f709b684e0bc676d70c41b3776c86a14d2c124dd088190f709b684e0bc676d70c41b3776c86a0114c86c0c7472616e7366657246726f6d1400000000000000000000000000000000000000010068164f6e746f6c6f67792e4e61746976652e496e766f6b65"

	payloadBytes, err := common.HexToBytes(payloadHex)
	assert.Nil(t, err)
	_, err = ParsePayload(payloadBytes)
	assert.Nil(t, err)
}

func TestParsePayloadRandom(t *testing.T) {
	testOntSdk = NewOntologySdk(sdk_utils.LAYER2_SDK)
	pri, err := common.HexToBytes("75de8489fcb2dcaf2ef3cd607feffde18789de7da129b5e97c81e001793cb7cf")
	assert.Nil(t, err)
	acc, err := NewAccountFromPrivateKey(pri, signature.SHA256withECDSA)
	assert.Nil(t, err)
	rand.Seed(time.Now().UnixNano())
	for i := 0; i < 1000000; i++ {
		amount := rand.Intn(1000000)
		state := &ont.State{
			From:  acc.Address,
			To:    acc.Address,
			Value: uint64(amount),
		}
		param := []*ont.State{state}
		invokeCode, err := utils.BuildNativeInvokeCode(ONT_CONTRACT_ADDRESS, 0, "transfer", []interface{}{param})
		res, err := ParsePayload(invokeCode)
		assert.Nil(t, err)
		if res["param"] == nil {
			fmt.Println("amount:", amount)
			fmt.Println(res["param"])
			return
		} else {
			stateInfos := res["param"].([]common2.StateInfo)
			assert.Equal(t, uint64(amount), stateInfos[0].Value)
		}
		tr := ont.TransferFrom{
			Sender: acc.Address,
			From:   acc.Address,
			To:     acc.Address,
			Value:  uint64(amount),
		}
		invokeCode, err = utils.BuildNativeInvokeCode(ONT_CONTRACT_ADDRESS, 0, "transferFrom", []interface{}{tr})
		res, err = ParsePayload(invokeCode)
		assert.Nil(t, err)
		if res["param"] == nil {
			fmt.Println("amount:", amount)
			fmt.Println(res["param"])
			return
		} else {
			stateInfos := res["param"].(common2.TransferFromInfo)
			assert.Equal(t, uint64(amount), stateInfos.Value)
		}
	}
}
func TestParsePayloadRandomMulti(t *testing.T) {
	testOntSdk = NewOntologySdk(sdk_utils.LAYER2_SDK)
	pri, err := common.HexToBytes("75de8489fcb2dcaf2ef3cd607feffde18789de7da129b5e97c81e001793cb7cf")
	assert.Nil(t, err)
	acc, err := NewAccountFromPrivateKey(pri, signature.SHA256withECDSA)
	assert.Nil(t, err)
	rand.Seed(time.Now().UnixNano())
	for i := 0; i < 100000; i++ {
		amount := rand.Intn(10000000)
		state := &ont.State{
			From:  acc.Address,
			To:    acc.Address,
			Value: uint64(amount),
		}
		paramLen := rand.Intn(20)
		if paramLen == 0 {
			paramLen += 1
		}
		params := make([]*ont.State, 0)
		for i := 0; i < paramLen; i++ {
			params = append(params, state)
		}
		invokeCode, err := utils.BuildNativeInvokeCode(ONT_CONTRACT_ADDRESS, 0, "transfer", []interface{}{params})
		res, err := ParsePayload(invokeCode)
		assert.Nil(t, err)
		if res["param"] == nil {
			fmt.Println(res["param"])
			fmt.Println(amount)
			fmt.Println("invokeCode:", common.ToHexString(invokeCode))
			return
		} else {
			stateInfos := res["param"].([]common2.StateInfo)
			for i := 0; i < paramLen; i++ {
				assert.Equal(t, uint64(amount), stateInfos[i].Value)
			}
		}
	}
}

func TestOntologySdk_TrabsferFrom(t *testing.T) {
	testOntSdk = NewOntologySdk(sdk_utils.LAYER2_SDK)
	payloadHex := "00c66b1421ab6ece5c9e44fa5e35261ef42cc6bc31d98e9c6a7cc814c1d2d106f9d2276b383958973b9fca8e4f48cc966a7cc80400e1f5056a7cc86c51c1087472616e736665721400000000000000000000000000000000000000020068164f6e746f6c6f67792e4e61746976652e496e766f6b65"
	payloadBytes, err := common.HexToBytes(payloadHex)
	assert.Nil(t, err)
	res, err := ParsePayload(payloadBytes)
	assert.Nil(t, err)
	fmt.Println("res:", res)

	//java sdk,  transferFrom
	//amount =100
	payloadHex = "00c66b14d2c124dd088190f709b684e0bc676d70c41b37766a7cc8149018fbdfe16d5b1054165ab892b0e040919bd1ca6a7cc8143e7c40c2a2a98e3f95adace19b12ef4a1d7a35066a7cc801646a7cc86c0c7472616e7366657246726f6d1400000000000000000000000000000000000000010068164f6e746f6c6f67792e4e61746976652e496e766f6b65"
	//amount =10
	//payloadHex = "00c66b14d2c124dd088190f709b684e0bc676d70c41b37766a7cc8149018fbdfe16d5b1054165ab892b0e040919bd1ca6a7cc8143e7c40c2a2a98e3f95adace19b12ef4a1d7a35066a7cc85a6a7cc86c0c7472616e7366657246726f6d1400000000000000000000000000000000000000010068164f6e746f6c6f67792e4e61746976652e496e766f6b65"

	//amount = 1000000000
	payloadHex = "00c66b14d2c124dd088190f709b684e0bc676d70c41b37766a7cc8149018fbdfe16d5b1054165ab892b0e040919bd1ca6a7cc8143e7c40c2a2a98e3f95adace19b12ef4a1d7a35066a7cc80400ca9a3b6a7cc86c0c7472616e7366657246726f6d1400000000000000000000000000000000000000010068164f6e746f6c6f67792e4e61746976652e496e766f6b65"

	//java sdk, transfer
	//amount = 100
	payloadHex = "00c66b14d2c124dd088190f709b684e0bc676d70c41b37766a7cc814d2c124dd088190f709b684e0bc676d70c41b37766a7cc801646a7cc86c51c1087472616e736665721400000000000000000000000000000000000000010068164f6e746f6c6f67792e4e61746976652e496e766f6b65"

	//amount = 10
	payloadHex = "00c66b14d2c124dd088190f709b684e0bc676d70c41b37766a7cc814d2c124dd088190f709b684e0bc676d70c41b37766a7cc85a6a7cc86c51c1087472616e736665721400000000000000000000000000000000000000010068164f6e746f6c6f67792e4e61746976652e496e766f6b65"
	//amount = 1000000000
	payloadHex = "00c66b14d2c124dd088190f709b684e0bc676d70c41b37766a7cc814d2c124dd088190f709b684e0bc676d70c41b37766a7cc80400ca9a3b6a7cc86c51c1087472616e736665721400000000000000000000000000000000000000010068164f6e746f6c6f67792e4e61746976652e496e766f6b65"

	payloadBytes, err = common.HexToBytes(payloadHex)
	assert.Nil(t, err)
	res, err = ParsePayload(payloadBytes)
	assert.Nil(t, err)
	fmt.Println("res:", res)
}

//transferFrom
func TestOntologySdk_ParseNativeTxPayload2(t *testing.T) {
	var err error
	assert.Nil(t, err)
	pri, err := common.HexToBytes("75de8489fcb2dcaf2ef3cd607feffde18789de7da129b5e97c81e001793cb7cf")
	acc, err := NewAccountFromPrivateKey(pri, signature.SHA256withECDSA)

	pri2, err := common.HexToBytes("75de8489fcb2dcaf2ef3cd607feffde18789de7da129b5e97c81e001793cb8cf")
	assert.Nil(t, err)

	pri3, err := common.HexToBytes("75de8489fcb2dcaf2ef3cd607feffde18789de7da129b5e97c81e001793cb9cf")
	assert.Nil(t, err)
	acc, err = NewAccountFromPrivateKey(pri, signature.SHA256withECDSA)

	acc2, err := NewAccountFromPrivateKey(pri2, signature.SHA256withECDSA)

	acc3, err := NewAccountFromPrivateKey(pri3, signature.SHA256withECDSA)
	amount := 1000000000
	txFrom, err := testOntSdk.Native.Ont.NewTransferFromTransaction(2500, 20000, acc.Address, acc2.Address, acc3.Address, uint64(amount))
	assert.Nil(t, err)
	tx, err := txFrom.IntoImmutable()
	assert.Nil(t, err)
	invokeCode, ok := tx.Payload.(*payload.InvokeCode)
	assert.True(t, ok)
	code := invokeCode.Code
	res, err := ParsePayload(code)
	assert.Nil(t, err)
	rp := res["param"].(common2.TransferFromInfo)
	assert.Equal(t, acc.Address.ToBase58(), rp.Sender)
	assert.Equal(t, acc2.Address.ToBase58(), rp.From)
	assert.Equal(t, uint64(amount), rp.Value)
	assert.Equal(t, "transferFrom", res["functionName"].(string))
	fmt.Println("res:", res)
}
func TestOntologySdk_ParseNativeTxPayload(t *testing.T) {
	testOntSdk = NewOntologySdk(sdk_utils.LAYER2_SDK)
	var err error
	assert.Nil(t, err)
	pri, err := common.HexToBytes("75de8489fcb2dcaf2ef3cd607feffde18789de7da129b5e97c81e001793cb7cf")
	acc, err := NewAccountFromPrivateKey(pri, signature.SHA256withECDSA)

	pri2, err := common.HexToBytes("75de8489fcb2dcaf2ef3cd607feffde18789de7da129b5e97c81e001793cb8cf")
	assert.Nil(t, err)

	pri3, err := common.HexToBytes("75de8489fcb2dcaf2ef3cd607feffde18789de7da129b5e97c81e001793cb9cf")
	assert.Nil(t, err)
	acc, err = NewAccountFromPrivateKey(pri, signature.SHA256withECDSA)

	acc2, err := NewAccountFromPrivateKey(pri2, signature.SHA256withECDSA)

	acc3, err := NewAccountFromPrivateKey(pri3, signature.SHA256withECDSA)
	y, _ := common.HexToBytes(acc.Address.ToHexString())

	fmt.Println("acc:", common.ToHexString(common.ToArrayReverse(y)))
	assert.Nil(t, err)

	amount := uint64(1000000000)
	tx, err := testOntSdk.Native.Ont.NewTransferTransaction(2500, 20000, acc.Address, acc2.Address, amount)
	assert.Nil(t, err)

	tx2, err := tx.IntoImmutable()
	assert.Nil(t, err)
	res, err := ParseNativeTxPayload(tx2.ToArray())
	assert.Nil(t, err)
	fmt.Println("res:", res)
	states := res["param"].([]common2.StateInfo)
	assert.Equal(t, acc.Address.ToBase58(), states[0].From)
	assert.Equal(t, acc2.Address.ToBase58(), states[0].To)
	assert.Equal(t, amount, states[0].Value)
	assert.Equal(t, "transfer", res["functionName"].(string))

	transferFrom, err := testOntSdk.Native.Ont.NewTransferFromTransaction(2500, 20000, acc.Address, acc2.Address, acc3.Address, 10)
	transferFrom2, err := transferFrom.IntoImmutable()
	r, err := ParseNativeTxPayload(transferFrom2.ToArray())
	assert.Nil(t, err)
	fmt.Println("res:", r)
	rp := r["param"].(common2.TransferFromInfo)
	assert.Equal(t, acc.Address.ToBase58(), rp.Sender)
	assert.Equal(t, acc2.Address.ToBase58(), rp.From)
	assert.Equal(t, uint64(10), rp.Value)

	ongTransfer, err := testOntSdk.Native.Ong.NewTransferTransaction(uint64(2500), uint64(20000), acc.Address, acc2.Address, 100000000)
	assert.Nil(t, err)
	ongTx, err := ongTransfer.IntoImmutable()
	assert.Nil(t, err)
	res, err = ParseNativeTxPayload(ongTx.ToArray())
	assert.Nil(t, err)
	fmt.Println("res:", res)
}

func TestOntologySdk_GenerateMnemonicCodesStr2(t *testing.T) {
	mnemonic := make(map[string]bool)
	testOntSdk := NewOntologySdk(sdk_utils.LAYER2_SDK)
	for i := 0; i < 100000; i++ {
		mnemonicStr, err := testOntSdk.GenerateMnemonicCodesStr()
		assert.Nil(t, err)
		if mnemonic[mnemonicStr] == true {
			panic("there is the same mnemonicStr ")
		} else {
			mnemonic[mnemonicStr] = true
		}
	}
}

func TestOntologySdk_GenerateMnemonicCodesStr(t *testing.T) {
	testOntSdk := NewOntologySdk(sdk_utils.LAYER2_SDK)
	for i := 0; i < 1000; i++ {
		mnemonic, err := testOntSdk.GenerateMnemonicCodesStr()
		assert.Nil(t, err)
		private, err := testOntSdk.GetPrivateKeyFromMnemonicCodesStrBip44(mnemonic, 0)
		assert.Nil(t, err)
		acc, err := NewAccountFromPrivateKey(private, signature.SHA256withECDSA)
		assert.Nil(t, err)
		si, err := signature.Sign(acc.SigScheme, acc.PrivateKey, []byte("test"), nil)
		boo := signature.Verify(acc.PublicKey, []byte("test"), si)
		assert.True(t, boo)

		tx, err := testOntSdk.Native.Ont.NewTransferTransaction(0, 0, acc.Address, acc.Address, 10)
		assert.Nil(t, err)
		testOntSdk.SignToTransaction(tx, acc)
		tx2, err := tx.IntoImmutable()
		assert.Nil(t, err)
		res := validation.VerifyTransaction(tx2)
		assert.Equal(t, "not an error", res.Error())
	}
}

func TestGenerateMemory(t *testing.T) {
	expectedPrivateKey := []string{"915f5df65c75afe3293ed613970a1661b0b28d0cb711f21c489d8785977df0cd", "dbf1090889ba8b19aa01fa31c8b1ce29828bd2fa664afd95cc62e6055b74e112",
		"1487a8e53e4f4e2e1991781bcd14b3d334d3b2965cb48c976b234da29d7cf242", "79f85da015f079469c6e04aa0fc23523187d0f72c29450073d858ddeed272617"}
	entropy, _ := bip39.NewEntropy(128)
	mnemonic, _ := bip39.NewMnemonic(entropy)
	mnemonic = "ecology cricket napkin scrap board purpose picnic toe bean heart coast retire"
	testOntSdk := NewOntologySdk(sdk_utils.LAYER2_SDK)
	for i := 0; i < len(expectedPrivateKey); i++ {
		privk, err := testOntSdk.GetPrivateKeyFromMnemonicCodesStrBip44(mnemonic, uint32(i))
		assert.Nil(t, err)
		assert.Equal(t, expectedPrivateKey[i], common.ToHexString(privk))
	}
}

func TestOntologySdk_CreateWallet(t *testing.T) {
	return
	wal, err := testOntSdk.CreateWallet("./wallet2.dat")
	assert.Nil(t, err)
	if err != nil {
		return
	}
	_, err = wal.NewDefaultSettingAccount(testPasswd)
	assert.Nil(t, err)
	wal.Save()
}

func TestNewOntologySdk(t *testing.T) {
	testOntSdk = NewOntologySdk(sdk_utils.LAYER2_SDK)
	testWallet, _ = testOntSdk.OpenWallet("./wallet.dat")
	event := &event.NotifyEventInfo{
		ContractAddress: common.ADDRESS_EMPTY,
		States:          []interface{}{"transfer", "Abc3UVbyL1kxd9sK6N9hzAT2u91ftbpoXT", "AFmseVrdL9f9oyCzZefL9tG6UbviEH9ugK", uint64(10000000)},
	}
	e, err := testOntSdk.ParseNaitveTransferEvent(event)
	assert.Nil(t, err)
	fmt.Println(e)
}

func TestOntologySdk_GetTxData(t *testing.T) {
	testOntSdk = NewOntologySdk(sdk_utils.LAYER2_SDK)
	testWallet, _ = testOntSdk.OpenWallet("./wallet.dat")
	acc, _ := testWallet.GetAccountByAddress("AXdmdzbyf3WZKQzRtrNQwAR91ZxMUfhXkt", testPasswd)
	tx, _ := testOntSdk.Native.Ont.NewTransferTransaction(2500, 10000, acc.Address, acc.Address, 100)
	testOntSdk.SignToTransaction(tx, acc)
	tx2, _ := tx.IntoImmutable()
	sink := common.NewZeroCopySink(nil)
	tx2.Serialization(sink)
	txData := hex.EncodeToString(sink.Bytes())
	tx3, _ := testOntSdk.GetMutableTx(txData)
	assert.Equal(t, tx, tx3)
}

func Init() {
	testOntSdk = NewOntologySdk(sdk_utils.LAYER2_SDK)
	testOntSdk.NewRpcClient(sdk_utils.LAYER2_SDK).SetAddress(testNetUrl)

	var err error
	var wallet *Wallet
	if !common.FileExisted("./wallet.dat") {
		wallet, err = testOntSdk.CreateWallet("./wallet.dat")
		if err != nil {
			fmt.Println("[CreateWallet] error:", err)
			return
		}
	} else {
		wallet, err = testOntSdk.OpenWallet("./wallet.dat")
		if err != nil {
			fmt.Println("[CreateWallet] error:", err)
			return
		}
	}
	_, err = wallet.NewDefaultSettingAccount(testPasswd)
	if err != nil {
		fmt.Println("")
		return
	}
	wallet.Save()
	testWallet, err = testOntSdk.OpenWallet("./wallet.dat")
	if err != nil {
		fmt.Printf("account.Open error:%s\n", err)
		return
	}
	testDefAcc, err = testWallet.GetDefaultAccount(testPasswd)
	if err != nil {
		fmt.Printf("GetDefaultAccount error:%s\n", err)
		return
	}

	return
	ws := testOntSdk.NewWebSocketClient(sdk_utils.LAYER2_SDK)
	err = ws.Connect("ws://localhost:20335")
	if err != nil {
		fmt.Printf("Connect ws error:%s", err)
		return
	}
}
