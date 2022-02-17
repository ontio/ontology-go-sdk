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
	"math/big"
	"testing"
	"time"

	"github.com/ontio/ontology/common"
	"github.com/ontio/ontology/common/constants"
	"github.com/stretchr/testify/assert"
)

func TestOnt_BalanceV2(t *testing.T) {
	testOntSdk = NewOntologySdk()
	testOntSdk.NewRpcClient().SetAddress(testNetUrl)
	testWallet, _ = testOntSdk.OpenWallet("./wallet.dat")
	testDefAcc, err := testWallet.GetDefaultAccount(testPasswd)
	assert.Nil(t, err)
	balance, err := testOntSdk.Native.Ont.BalanceOfV2(testDefAcc.Address)
	assert.Nil(t, err)
	t.Logf("balance:%d", balance)
}

func TestOng_BalanceV2(t *testing.T) {
	testOntSdk = NewOntologySdk()
	testOntSdk.NewRpcClient().SetAddress(testNetUrl)
	testWallet, _ = testOntSdk.OpenWallet("./wallet.dat")
	testDefAcc, err := testWallet.GetDefaultAccount(testPasswd)
	assert.Nil(t, err)
	balance, err := testOntSdk.Native.Ong.BalanceOfV2(testDefAcc.Address)
	assert.Nil(t, err)
	t.Logf("balance:%v", balance)
}

func TestOnt_DecimalsV2(t *testing.T) {
	testOntSdk = NewOntologySdk()
	testOntSdk.NewRpcClient().SetAddress(testNetUrl)
	res, err := testOntSdk.Native.Ont.DecimalsV2()
	assert.Nil(t, err)
	assert.Equal(t, 9, int(res))
}

func TestOng_DecimalsV2(t *testing.T) {
	testOntSdk = NewOntologySdk()
	testOntSdk.NewRpcClient().SetAddress(testNetUrl)
	res, err := testOntSdk.Native.Ong.DecimalsV2()
	assert.Nil(t, err)
	assert.Equal(t, 18, int(res))
}

func TestOnt_TotalSupplyV2(t *testing.T) {
	testOntSdk = NewOntologySdk()
	testOntSdk.NewRpcClient().SetAddress(testNetUrl)
	res, err := testOntSdk.Native.Ont.TotalSupplyV2()
	assert.Nil(t, err)
	assert.Equal(t, new(big.Int).SetInt64(constants.ONT_TOTAL_SUPPLY_V2), res)
}

func TestOng_TotalSupplyV2(t *testing.T) {
	testOntSdk = NewOntologySdk()
	testOntSdk.NewRpcClient().SetAddress(testNetUrl)
	res, err := testOntSdk.Native.Ong.TotalSupplyV2()
	assert.Nil(t, err)
	t.Logf("rest:%v", res)
	assert.Equal(t, common.BigIntToNeoBytes(constants.ONG_TOTAL_SUPPLY_V2.BigInt()), bytesReverse(res.Bytes()))
}

func bytesReverse(u []byte) []byte {
	for i, j := 0, len(u)-1; i < j; i, j = i+1, j-1 {
		u[i], u[j] = u[j], u[i]
	}
	return u
}

func TestOng_UnboundONGV2(t *testing.T) {
	testOntSdk = NewOntologySdk()
	testOntSdk.NewRpcClient().SetAddress(testNetUrl)
	testWallet, _ = testOntSdk.OpenWallet("./wallet.dat")
	testDefAcc, err := testWallet.GetDefaultAccount(testPasswd)
	assert.Nil(t, err)
	res, err := testOntSdk.Native.Ong.UnboundONGV2(testDefAcc.Address)
	assert.Nil(t, err)
	t.Logf("res:%v", res)
}

func TestOnt_TransferV2(t *testing.T) {
	testOntSdk = NewOntologySdk()
	testOntSdk.NewRpcClient().SetAddress(testNetUrl)
	testWallet, _ = testOntSdk.OpenWallet("./wallet.dat")
	testDefAcc, err := testWallet.GetDefaultAccount(testPasswd)
	assert.Nil(t, err)
	addr, err := common.AddressFromBase58("AWRBh9yYVzYHAfAb3tuWtdKjwGxNubimPo")
	assert.Nil(t, err)
	txHash, err := testOntSdk.Native.Ont.TransferV2(testGasPrice, testGasLimit, nil, testDefAcc, addr, new(big.Int).SetInt64(98))
	assert.Nil(t, err)
	t.Logf("hash:%v", txHash.ToHexString())

}

func TestOng_TransferV2(t *testing.T) {
	testOntSdk = NewOntologySdk()
	testOntSdk.NewRpcClient().SetAddress(testNetUrl)
	testWallet, _ = testOntSdk.OpenWallet("./wallet.dat")
	testDefAcc, err := testWallet.GetDefaultAccount(testPasswd)
	assert.Nil(t, err)
	addr, err := common.AddressFromBase58("AWRBh9yYVzYHAfAb3tuWtdKjwGxNubimPo")
	assert.Nil(t, err)
	txHash, err := testOntSdk.Native.Ong.TransferV2(testGasPrice, testGasLimit, nil, testDefAcc, addr, new(big.Int).SetInt64(10000000000887776))
	assert.Nil(t, err)
	t.Logf("hash:%v", txHash.ToHexString())
	_, err = testOntSdk.WaitForGenerateBlock(30 * time.Second)
	assert.Nil(t, err)
	contractEvent, err := testOntSdk.GetSmartContractEvent(txHash.ToHexString())
	assert.Nil(t, err)
	for _, notify := range contractEvent.Notify {
		transfer, err := testOntSdk.ParseNativeTransferEventV2(notify)
		assert.Nil(t, err)
		t.Logf("transfer:%v", transfer)
	}
}

func TestOng_Transfer(t *testing.T) {
	testOntSdk = NewOntologySdk()
	testOntSdk.NewRpcClient().SetAddress(testNetUrl)
	testWallet, _ = testOntSdk.OpenWallet("./wallet.dat")
	testDefAcc, err := testWallet.GetDefaultAccount(testPasswd)
	assert.Nil(t, err)
	addr, err := common.AddressFromBase58("AWRBh9yYVzYHAfAb3tuWtdKjwGxNubimPo")
	assert.Nil(t, err)
	txHash, err := testOntSdk.Native.Ong.TransferV2(testGasPrice, testGasLimit, nil, testDefAcc, addr, new(big.Int).SetInt64(17))
	assert.Nil(t, err)
	t.Logf("hash:%v", txHash.ToHexString())
}

func TestOnt_NewTransferTransactionV2(t *testing.T) {
	testOntSdk = NewOntologySdk()
	testOntSdk.NewRpcClient().SetAddress(testNetUrl)
	testWallet, _ = testOntSdk.OpenWallet("./wallet.dat")
	testDefAcc, err := testWallet.GetDefaultAccount(testPasswd)
	assert.Nil(t, err)
	toAddr, err := common.AddressFromBase58("AWRBh9yYVzYHAfAb3tuWtdKjwGxNubimPo")
	assert.Nil(t, err)
	mutableTransaction, err := testOntSdk.Native.Ont.NewTransferTransactionV2(testGasPrice, testGasLimit, testDefAcc.Address, toAddr, new(big.Int).SetInt64(1111111111125))
	assert.Nil(t, err)
	ontTx, err := mutableTransaction.IntoImmutable()
	assert.Nil(t, err)
	res, err := ParseNativeTxPayloadV2(ontTx.ToArray())
	assert.Nil(t, err)
	t.Logf("res:%v", res)
}

func TestOnt_NewTransferTransaction(t *testing.T) {
	testOntSdk = NewOntologySdk()
	testOntSdk.NewRpcClient().SetAddress(testNetUrl)
	testWallet, _ = testOntSdk.OpenWallet("./wallet.dat")
	testDefAcc, err := testWallet.GetDefaultAccount(testPasswd)
	assert.Nil(t, err)
	toAddr, err := common.AddressFromBase58("AWRBh9yYVzYHAfAb3tuWtdKjwGxNubimPo")
	assert.Nil(t, err)
	mutableTransaction, err := testOntSdk.Native.Ont.NewTransferTransaction(testGasPrice, testGasLimit, testDefAcc.Address, toAddr, 111111125)
	assert.Nil(t, err)
	ontTx, err := mutableTransaction.IntoImmutable()
	assert.Nil(t, err)
	res, err := ParseNativeTxPayload(ontTx.ToArray())
	assert.Nil(t, err)
	t.Logf("res:%v", res)
}

func TestOng_NewTransferTransactionV2(t *testing.T) {
	testOntSdk = NewOntologySdk()
	testOntSdk.NewRpcClient().SetAddress(testNetUrl)
	testWallet, _ = testOntSdk.OpenWallet("./wallet.dat")
	testDefAcc, err := testWallet.GetDefaultAccount(testPasswd)
	assert.Nil(t, err)
	toAddr, err := common.AddressFromBase58("AWRBh9yYVzYHAfAb3tuWtdKjwGxNubimPo")
	assert.Nil(t, err)
	mutableTransaction, err := testOntSdk.Native.Ong.NewTransferTransactionV2(testGasPrice, testGasLimit, testDefAcc.Address, toAddr, new(big.Int).SetInt64(889100112999999025))
	assert.Nil(t, err)
	ongTx, err := mutableTransaction.IntoImmutable()
	assert.Nil(t, err)
	res, err := ParseNativeTxPayloadV2(ongTx.ToArray())
	assert.Nil(t, err)
	t.Logf("res:%v", res)
}

func TestOnt_NewTransferFromTransactionV2(t *testing.T) {
	testOntSdk = NewOntologySdk()
	testOntSdk.NewRpcClient().SetAddress(testNetUrl)
	testWallet, _ = testOntSdk.OpenWallet("./wallet.dat")
	testDefAcc, err := testWallet.GetDefaultAccount(testPasswd)
	assert.Nil(t, err)
	toAddr, err := common.AddressFromBase58("AWRBh9yYVzYHAfAb3tuWtdKjwGxNubimPo")
	assert.Nil(t, err)
	mutableTransaction, err := testOntSdk.Native.Ont.NewTransferFromTransactionV2(testGasPrice, testGasLimit, testDefAcc.Address, testDefAcc.Address, toAddr, new(big.Int).SetInt64(1111111111125))
	assert.Nil(t, err)
	ontTx, err := mutableTransaction.IntoImmutable()
	assert.Nil(t, err)
	res, err := ParseNativeTxPayloadV2(ontTx.ToArray())
	assert.Nil(t, err)
	t.Logf("res:%v", res)
}

func TestOng_NewTransferFromTransactionV2(t *testing.T) {
	testOntSdk = NewOntologySdk()
	testOntSdk.NewRpcClient().SetAddress(testNetUrl)
	testWallet, _ = testOntSdk.OpenWallet("./wallet.dat")
	testDefAcc, err := testWallet.GetDefaultAccount(testPasswd)
	assert.Nil(t, err)
	toAddr, err := common.AddressFromBase58("AWRBh9yYVzYHAfAb3tuWtdKjwGxNubimPo")
	assert.Nil(t, err)
	mutableTransaction, err := testOntSdk.Native.Ong.NewTransferFromTransactionV2(testGasPrice, testGasLimit, testDefAcc.Address, testDefAcc.Address, toAddr, new(big.Int).SetInt64(100000000000000008))
	assert.Nil(t, err)
	ontTx, err := mutableTransaction.IntoImmutable()
	assert.Nil(t, err)
	res, err := ParseNativeTxPayloadV2(ontTx.ToArray())
	assert.Nil(t, err)
	t.Logf("res:%v", res)
}
