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
	"math/rand"
	"strconv"
	"testing"
	"time"

	"github.com/ontio/ontology/core/payload"

	"github.com/ontio/ontology-crypto/signature"
	sdkcom "github.com/ontio/ontology-go-sdk/common"
	"github.com/ontio/ontology/common"
	"github.com/ontio/ontology/core/utils"
	"github.com/ontio/ontology/core/validation"
	"github.com/ontio/ontology/smartcontract/event"
	"github.com/ontio/ontology/smartcontract/service/native/ont"
	"github.com/stretchr/testify/assert"
	"github.com/tyler-smith/go-bip39"
)

var (
	testOntSdk   *OntologySdk
	testWallet   *Wallet
	testPasswd   = []byte("123456")
	testDefAcc   *Account
	testGasPrice = uint64(2500)
	testGasLimit = uint64(20000)
	testNetUrl   = "http://127.0.0.1:20336"
)

func init() {
	var err error
	testWallet, err = testOntSdk.OpenWallet("./wallet.dat")
	if err != nil {
		fmt.Printf("OpenWallet err: %s\n", err)
		return
	}
	testOntSdk = NewOntologySdk()
	testOntSdk.NewRpcClient().SetAddress(testNetUrl)
	testDefAcc, err = testWallet.GetDefaultAccount(testPasswd)
	if err != nil {
		fmt.Printf("GetDefaultAccount err: %s\n", err)
		return
	}
}
func TestOntId_NewRegIDWithAttributesTransaction(t *testing.T) {
	testOntSdk = NewOntologySdk()
}
func TestParseNativeTxPayload(t *testing.T) {
	testOntSdk = NewOntologySdk()
	pri, err := common.HexToBytes("75de8489fcb2dcaf2ef3cd607feffde18789de7da129b5e97c81e001793cb7cf")
	assert.Nil(t, err)
	acc, err := NewAccountFromPrivateKey(pri, signature.SHA256withECDSA)
	assert.Nil(t, err)
	state := &sdkcom.TransferState{
		From:  acc.Address,
		To:    acc.Address,
		Value: uint64(100),
	}
	transfers := make([]*sdkcom.TransferState, 0)
	for i := 0; i < 1; i++ {
		transfers = append(transfers, state)
	}
	_, err = testOntSdk.Native.Ont.NewMultiTransferTransaction(2500, 20000, transfers)
	assert.Nil(t, err)
	_, err = testOntSdk.Native.Ont.NewTransferFromTransaction(2500, 20000, acc.Address, acc.Address, acc.Address, 20)
	assert.Nil(t, err)
}

func TestParsePayload(t *testing.T) {
	testOntSdk = NewOntologySdk()
	payloadHex := "00c66b1421ab6ece5c9e44fa5e35261ef42cc6bc31d98e9c6a7cc814c1d2d106f9d2276b383958973b9fca8e4f48cc966a7cc80400e1f5056a7cc86c51c1087472616e736665721400000000000000000000000000000000000000020068164f6e746f6c6f67792e4e61746976652e496e766f6b65"

	payloadBytes, err := common.HexToBytes(payloadHex)
	assert.Nil(t, err)
	_, err = ParsePayload(payloadBytes)
	assert.Nil(t, err)
}

func TestParsePayloadRandom(t *testing.T) {
	testOntSdk = NewOntologySdk()
	pri, err := common.HexToBytes("75de8489fcb2dcaf2ef3cd607feffde18789de7da129b5e97c81e001793cb7cf")
	assert.Nil(t, err)
	acc, err := NewAccountFromPrivateKey(pri, signature.SHA256withECDSA)
	assert.Nil(t, err)
	rand.Seed(time.Now().UnixNano())
	for i := 0; i < 1000000; i++ {
		amount := rand.Intn(1000000)
		state := &ont.TransferState{
			From:  acc.Address,
			To:    acc.Address,
			Value: uint64(amount),
		}
		param := []*ont.TransferState{state}
		invokeCode, err := utils.BuildNativeInvokeCode(ONT_CONTRACT_ADDRESS, 0, "transfer", []interface{}{param})
		res, err := ParsePayload(invokeCode)
		assert.Nil(t, err)
		if res["param"] == nil {
			fmt.Println("amount:", amount)
			fmt.Println(res["param"])
			return
		} else {
			stateInfos := res["param"].([]sdkcom.StateInfo)
			assert.Equal(t, uint64(amount), stateInfos[0].Value)
		}
		tr := ont.TransferFrom{
			Sender: acc.Address,
			TransferState: ont.TransferState{
				From:  acc.Address,
				To:    acc.Address,
				Value: uint64(amount),
			},
		}
		invokeCode, err = utils.BuildNativeInvokeCode(ONT_CONTRACT_ADDRESS, 0, "transferFrom", []interface{}{tr})
		res, err = ParsePayload(invokeCode)
		assert.Nil(t, err)
		if res["param"] == nil {
			fmt.Println("amount:", amount)
			fmt.Println(res["param"])
			return
		} else {
			stateInfos := res["param"].(sdkcom.TransferFromInfo)
			assert.Equal(t, uint64(amount), stateInfos.Value)
		}
	}
}
func TestParsePayloadRandomMulti(t *testing.T) {
	testOntSdk = NewOntologySdk()
	pri, err := common.HexToBytes("75de8489fcb2dcaf2ef3cd607feffde18789de7da129b5e97c81e001793cb7cf")
	assert.Nil(t, err)
	acc, err := NewAccountFromPrivateKey(pri, signature.SHA256withECDSA)
	assert.Nil(t, err)
	rand.Seed(time.Now().UnixNano())
	for i := 0; i < 100000; i++ {
		amount := rand.Intn(10000000)
		state := &ont.TransferState{
			From:  acc.Address,
			To:    acc.Address,
			Value: uint64(amount),
		}
		paramLen := rand.Intn(20)
		if paramLen == 0 {
			paramLen += 1
		}
		params := make([]*ont.TransferState, 0)
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
			stateInfos := res["param"].([]sdkcom.StateInfo)
			for i := 0; i < paramLen; i++ {
				assert.Equal(t, uint64(amount), stateInfos[i].Value)
			}
		}
	}
}

func TestOntologySdk_TrabsferFrom(t *testing.T) {
	testOntSdk = NewOntologySdk()
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
	rp := res["param"].(sdkcom.TransferFromInfo)
	assert.Equal(t, acc.Address.ToBase58(), rp.Sender)
	assert.Equal(t, acc2.Address.ToBase58(), rp.From)
	assert.Equal(t, uint64(amount), rp.Value)
	assert.Equal(t, "transferFrom", res["functionName"].(string))
	fmt.Println("res:", res)
}
func TestOntologySdk_ParseNativeTxPayload(t *testing.T) {
	testOntSdk = NewOntologySdk()
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
	states := res["param"].([]sdkcom.StateInfo)
	assert.Equal(t, acc.Address.ToBase58(), states[0].From)
	assert.Equal(t, acc2.Address.ToBase58(), states[0].To)
	assert.Equal(t, amount, states[0].Value)
	assert.Equal(t, "transfer", res["functionName"].(string))

	transferFrom, err := testOntSdk.Native.Ont.NewTransferFromTransaction(2500, 20000, acc.Address, acc2.Address, acc3.Address, 10)
	transferFrom2, err := transferFrom.IntoImmutable()
	r, err := ParseNativeTxPayload(transferFrom2.ToArray())
	assert.Nil(t, err)
	fmt.Println("res:", r)
	rp := r["param"].(sdkcom.TransferFromInfo)
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
	testOntSdk := NewOntologySdk()
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
	testOntSdk := NewOntologySdk()
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
	testOntSdk := NewOntologySdk()
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
	testOntSdk = NewOntologySdk()
	testWallet, _ = testOntSdk.OpenWallet("./wallet.dat")
	event := &event.NotifyEventInfo{
		ContractAddress: common.ADDRESS_EMPTY,
		States:          []interface{}{"transfer", "Abc3UVbyL1kxd9sK6N9hzAT2u91ftbpoXT", "AFmseVrdL9f9oyCzZefL9tG6UbviEH9ugK", uint64(10000000)},
	}
	e, err := testOntSdk.ParseNativeTransferEvent(event)
	assert.Nil(t, err)
	fmt.Println(e)
}

func TestOntologySdk_GetTxData(t *testing.T) {
	testOntSdk = NewOntologySdk()
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

func TestOntologySdk_VerifyLayer2StoreProof(t *testing.T) {
	testLayer2Sdk := NewLayer2Sdk()
	key, _ := hex.DecodeString("050946e00bcd8be898e60b79ace69e082732bc807668656c6c6f")
	value, _ := hex.DecodeString("001174686973206973206578616d706c652058")
	proof, _ := hex.DecodeString("050000000513000000000000002a0000000000000020a8e6e09eaaffc9224e77d77da73bf3de391822f10a5e891a33432313cb31728800040a000000000000002a0000000000000020e89e44cb23ceaa71640cdcef34b147d70b22b07ae6464ef95b39b1853651b35300030500000000000000260000000000000020d5779fd4f428a09cdcf3be8b31cb3e5e16f4c21ada3c1541a22c4272256f2fe300020300000000000000260000000000000020b8cfb72dbafa6db660df5aaa5713a94cd8e6399aa36026dc052534812a4893d70001020000000000000026000000000000002083a7e854f781894fae08eb636cdb932ff799237e52f0039b714ae50aeb896fc10000000000010000001a050946e00bcd8be898e60b79ace69e082732bc807668656c6c6f20aa4a40856844e60c5c80b5b30041c3ec7cd0d17a6e34933be621cb546c70ca362600000000000000")
	stateRoot, _ := hex.DecodeString("5d1cce9f5f8e12185a3482d35aec21b34d6e4c0112aff75adf0bc435c9f9e97d")
	result, err := testLayer2Sdk.VerifyLayer2StoreProof(key, value, proof, stateRoot)
	assert.Equal(t, nil, err)
	assert.Equal(t, true, result)
}

func Init() {
	testOntSdk = NewOntologySdk()
	testOntSdk.NewRpcClient().SetAddress(testNetUrl)

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
	ws := testOntSdk.NewWebSocketClient()
	err = ws.Connect("ws://localhost:20335")
	if err != nil {
		fmt.Printf("Connect ws error:%s", err)
		return
	}
}

func TestOnt_Transfer(t *testing.T) {
	return
	Init()
	testOntSdk = NewOntologySdk()
	testOntSdk.NewRpcClient().SetAddress(testNetUrl)
	testWallet, _ = testOntSdk.OpenWallet("./wallet.dat")
	txHash, err := testOntSdk.Native.Ont.Transfer(testGasPrice, testGasLimit, nil, testDefAcc, testDefAcc.Address, 1)
	if err != nil {
		t.Errorf("NewTransferTransaction error:%s", err)
		return
	}
	testOntSdk.WaitForGenerateBlock(30*time.Second, 1)
	evts, err := testOntSdk.GetSmartContractEvent(txHash.ToHexString())
	if err != nil {
		t.Errorf("GetSmartContractEvent error:%s", err)
		return
	}
	fmt.Printf("TxHash:%s\n", txHash.ToHexString())
	fmt.Printf("State:%d\n", evts.State)
	fmt.Printf("GasConsume:%d\n", evts.GasConsumed)
	for _, notify := range evts.Notify {
		fmt.Printf("ContractAddress:%s\n", notify.ContractAddress)
		fmt.Printf("States:%+v\n", notify.States)
	}
}

func TestOng_WithDrawONG(t *testing.T) {
	Init()
	unboundONG, err := testOntSdk.Native.Ong.UnboundONG(testDefAcc.Address)
	if err != nil {
		t.Errorf("UnboundONG error:%s", err)
		return
	}
	fmt.Printf("Address:%s UnboundONG:%d\n", testDefAcc.Address.ToBase58(), unboundONG)
	_, err = testOntSdk.Native.Ong.WithdrawONG(2500, 20000, nil, testDefAcc, unboundONG)
	if err != nil {
		t.Errorf("WithDrawONG error:%s", err)
		return
	}
	fmt.Printf("Address:%s WithDrawONG amount:%d success\n", testDefAcc.Address.ToBase58(), unboundONG)
}

func TestGlobalParam_GetGlobalParams(t *testing.T) {
	Init()
	gasPrice := "gasPrice"
	params := []string{gasPrice}
	results, err := testOntSdk.Native.GlobalParams.GetGlobalParams(params)
	if err != nil {
		t.Errorf("GetGlobalParams:%+v error:%s", params, err)
		return
	}
	fmt.Printf("Params:%s Value:%v\n", gasPrice, results[gasPrice])
}

func TestGlobalParam_SetGlobalParams(t *testing.T) {
	return
	Init()
	gasPrice := "gasPrice"
	globalParams, err := testOntSdk.Native.GlobalParams.GetGlobalParams([]string{gasPrice})
	if err != nil {
		t.Errorf("GetGlobalParams error:%s", err)
		return
	}
	gasPriceValue, err := strconv.Atoi(globalParams[gasPrice])
	if err != nil {
		t.Errorf("Get prama value error:%s", err)
		return
	}
	_, err = testOntSdk.Native.GlobalParams.SetGlobalParams(testGasPrice, testGasLimit, nil, testDefAcc, map[string]string{gasPrice: strconv.Itoa(gasPriceValue + 1)})
	if err != nil {
		t.Errorf("SetGlobalParams error:%s", err)
		return
	}
	testOntSdk.WaitForGenerateBlock(30*time.Second, 1)
	globalParams, err = testOntSdk.Native.GlobalParams.GetGlobalParams([]string{gasPrice})
	if err != nil {
		t.Errorf("GetGlobalParams error:%s", err)
		return
	}
	gasPriceValueAfter, err := strconv.Atoi(globalParams[gasPrice])
	if err != nil {
		t.Errorf("Get prama value error:%s", err)
		return
	}
	fmt.Printf("After set params gasPrice:%d\n", gasPriceValueAfter)
}

func TestWsScribeEvent(t *testing.T) {
	return
	Init()
	wsClient := testOntSdk.ClientMgr.GetWebSocketClient()
	err := wsClient.SubscribeEvent()
	if err != nil {
		t.Errorf("SubscribeTxHash error:%s", err)
		return
	}
	defer wsClient.UnsubscribeTxHash()

	actionCh := wsClient.GetActionCh()
	timer := time.NewTimer(time.Minute * 3)
	for {
		select {
		case <-timer.C:
			return
		case action := <-actionCh:
			fmt.Printf("Action:%s\n", action.Action)
			fmt.Printf("Result:%s\n", action.Result)
		}
	}
}

func TestWsTransfer(t *testing.T) {
	return
	Init()
	wsClient := testOntSdk.ClientMgr.GetWebSocketClient()
	testOntSdk.ClientMgr.SetDefaultClient(wsClient)
	txHash, err := testOntSdk.Native.Ont.Transfer(testGasPrice, testGasLimit, nil, testDefAcc, testDefAcc.Address, 1)
	if err != nil {
		t.Errorf("NewTransferTransaction error:%s", err)
		return
	}
	testOntSdk.WaitForGenerateBlock(30*time.Second, 1)
	evts, err := testOntSdk.GetSmartContractEvent(txHash.ToHexString())
	if err != nil {
		t.Errorf("GetSmartContractEvent error:%s", err)
		return
	}
	fmt.Printf("TxHash:%s\n", txHash.ToHexString())
	fmt.Printf("State:%d\n", evts.State)
	fmt.Printf("GasConsume:%d\n", evts.GasConsumed)
	for _, notify := range evts.Notify {
		fmt.Printf("ContractAddress:%s\n", notify.ContractAddress)
		fmt.Printf("States:%+v\n", notify.States)
	}
}
