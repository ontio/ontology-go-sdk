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
package rest

import (
	"bytes"
	"fmt"
	"github.com/ontio/ontology-crypto/keypair"
	s "github.com/ontio/ontology-crypto/signature"
	"github.com/ontio/ontology-go-sdk/utils"
	"github.com/ontio/ontology/account"
	"github.com/ontio/ontology/common/constants"
	"github.com/ontio/ontology/common/serialization"
	"github.com/ontio/ontology/core/payload"
	"github.com/ontio/ontology/core/types"
	"github.com/ontio/ontology/smartcontract/service/native/ont"
	nvutils "github.com/ontio/ontology/smartcontract/service/native/utils"
	"os"
	"testing"
	"time"
)

//RpcClient instance of test only
var (
	testRest   *RestClient
	testWallet account.Client
	testPasswd = []byte("wangbing")
)

func TestMain(t *testing.M) {
	var err error
	testRest = NewRestClient()
	testRest.SetAddress("http://localhost:20334")
	walletFile := "./wallet.dat"
	testWallet, err = account.Open(walletFile)
	if err != nil {
		fmt.Errorf("wallet open error:%s", err)
		return
	}
	accMeta := testWallet.GetAccountMetadataByLabel("t")
	if accMeta == nil {
		_, err = testWallet.NewAccount("t", keypair.PK_ECDSA, keypair.P256, s.SHA256withECDSA, testPasswd)
		if err != nil {
			fmt.Errorf("NewAccount error:%s", err)
			return
		}
	}

	t.Run()
	os.RemoveAll("./ActorLog")
}

func TestGetVersion(t *testing.T) {
	version, err := testRest.GetVersion()
	if err != nil {
		t.Errorf("TestGetVersion GetVersion error:%s", err)
		return
	}
	fmt.Printf("Version:%s\n", version)
}

func TestGetNetworkId(t *testing.T) {
	networkId, err := testRest.GetNetworkId()
	if err != nil {
		t.Errorf("GetNetworkId error:%s", err)
		return
	}
	fmt.Printf("NetworkId:%d\n", networkId)
}

func TestGetBlockByHash(t *testing.T) {
	blockHash, err := testRest.GetBlockHash(0)
	if err != nil {
		t.Errorf("GetBlockHash error:%s", err)
		return
	}
	block, err := testRest.GetBlockByHash(blockHash)
	if err != nil {
		t.Errorf("GetBlockByHash error:%s", err)
		return
	}
	fmt.Printf("TestGetBlockByHash BlockHeight:%d BlockHash:%x\n", block.Header.Height, block.Hash())
}

func TestGetBlockByHeight(t *testing.T) {
	block, err := testRest.GetBlockByHeight(0)
	if err != nil {
		t.Errorf("GetBlockByHash error:%s", err)
		return
	}
	fmt.Printf("TestGetBlockByHeight BlockHeight:%d BlockHash:%x\n", block.Header.Height, block.Hash())
}

func TestGetCurrentBlockHeight(t *testing.T) {
	count, err := testRest.GetCurrentBlockHeight()
	if err != nil {
		t.Errorf("GetCurrentBlockHeight error:%s", err)
		return
	}
	fmt.Printf("TestGetCurrentBlockHeight CurrentBlockHeight:%d\n", count)
}

func TestGetBalance(t *testing.T) {
	defAcc, _ := testWallet.GetDefaultAccount(testPasswd)
	balance, err := testRest.GetBalance(defAcc.Address)
	if err != nil {
		t.Errorf("GetBalance error:%s", err)
		return
	}
	fmt.Printf("Balance ONT:%d\n", balance.Ont)
	fmt.Printf("Balance ONG:%d\n", balance.Ong)
}

func TestGetBlockHash(t *testing.T) {
	blockHash, err := testRest.GetBlockHash(0)
	if err != nil {
		t.Errorf("GetBlockHash error:%s", err)
		return
	}
	fmt.Printf("TestGetBlockHash %x\n", blockHash)
}

func TestGetStorage(t *testing.T) {
	value, err := testRest.GetStorage(nvutils.OntContractAddress, []byte(ont.TOTALSUPPLY_NAME))
	if err != nil {
		t.Errorf("TestGetStorage error:%s", err)
		return
	}
	if value == nil {
		t.Errorf("TestGetStorage value is nil")
		return
	}
	totalSupply, err := serialization.ReadUint64(bytes.NewReader(value))
	if err != nil {
		t.Errorf("TestGetStorage serialization.ReadUint64 error:%s", err)
		return
	}
	if totalSupply != constants.ONT_TOTAL_SUPPLY {
		t.Errorf("TestGetStorage totalSupply %d != %d", totalSupply, constants.ONT_TOTAL_SUPPLY)
		return
	}
	fmt.Printf("TestGetStorage %d\n", totalSupply)
}

func TestGetMemPoolTxCount(t *testing.T) {
	count, err := testRest.GetMemPoolTxCount()
	if err != nil {
		t.Errorf("GetMemPoolTxCount error:%s", err)
		return
	}
	fmt.Printf("MemPoolTxCount:%+v\n", count)
}

func TestGetMemPoolTxState(t *testing.T) {
	defAcc, err := testWallet.GetDefaultAccount(testPasswd)
	if err != nil {
		t.Errorf("GetDefaultAccount error:%s", err)
		return
	}
	txHash, err := testRest.Transfer(0, 20000, "ont", defAcc, defAcc.Address, 10)
	if err != nil {
		t.Errorf("Transfer error:%s", err)
		return
	}
	state, err := testRest.GetMemPoolTxState(txHash)
	if err != nil {
		t.Errorf("GetMemPoolTxState error:%s", err)
		return
	}
	for _, stateItem := range state.State {
		fmt.Printf("State:%+v\n", stateItem)
	}
}

func TestGetBlockHeightByTxHash(t *testing.T) {
	defAcc, err := testWallet.GetDefaultAccount(testPasswd)
	if err != nil {
		t.Errorf("GetDefaultAccount error:%s", err)
		return
	}
	txHash, err := testRest.Transfer(0, 20000, "ont", defAcc, defAcc.Address, 10)
	if err != nil {
		t.Errorf("Transfer error:%s", err)
		return
	}
	testRest.WaitForGenerateBlock(30*time.Second, 1)
	height, err := testRest.GetBlockHeightByTxHash(txHash)
	if err != nil {
		t.Errorf("GetBlockHeightByTxHash error:%s", err)
		return
	}
	fmt.Printf("TxHash:%s BlockHeight:%d\n", txHash.ToHexString(), height)
}

func TestGetBlockTxHashesByHeight(t *testing.T) {
	height, err := testRest.GetCurrentBlockHeight()
	if err != nil {
		t.Errorf("GetBlockCount error:%s", err)
		return
	}
	blockTxHashes, err := testRest.GetBlockTxHashesByHeight(height)
	if err != nil {
		t.Errorf("GetBlockTxHashesByHeight error:%s", err)
		return
	}
	fmt.Printf("BlockHeight:%d\n", blockTxHashes.Height)
	fmt.Printf("TxHashes:%d\n", len(blockTxHashes.Transactions))
	for _, tx := range blockTxHashes.Transactions {
		fmt.Printf("Tx:%s\n", tx.ToHexString())
	}
}

func TestGetSmartContractEvent(t *testing.T) {
	events, err := testRest.GetSmartContractEventByBlock(0)
	if err != nil {
		t.Errorf("GetSmartContractEventByBlock error:%s", err)
		return
	}

	scEvt, err := testRest.GetSmartContractEventWithHexString(events[0].TxHash)
	if err != nil {
		t.Errorf("GetSmartContractEvent error:%s", err)
		return
	}
	//Sample:
	//{
	//	"TxHash": "a0cdac22f3e0554ec41bd4e8a2d151b6a6e178fcb194b449cfb13f1f22dbe8e7",
	//	"State": 1,
	//	"GasConsumed": 0,
	//	"Notify": [
	//		{
	//			"ContractAddress": "ff00000000000000000000000000000000000001",
	//			"States": [
	//				"transfer",
	//				"TA9PGG2Ze5RDYXy8mYjo9Brw2WLzthncH2",
	//				"TA4WwfrGEjcrRPQCCp6nS2f9ymRHmzeCgj",
	//				10
	//			]
	//		}
	//	]
	//}

	fmt.Printf(" TxHash:%s\n", scEvt.TxHash)
	fmt.Printf(" State:%d\n", scEvt.State)
	fmt.Printf(" GasConsumed:%d\n", scEvt.GasConsumed)
	for _, notify := range scEvt.Notify {
		fmt.Printf(" SmartContractAddress:%s\n", notify.ContractAddress)
		states := notify.States.([]interface{})
		name := states[0].(string)
		from := states[1].(string)
		to := states[2].(string)
		value := states[3].(float64)
		fmt.Printf(" State Name:%s from:%s to:%s value:%d\n", name, from, to, int(value))
	}
}

func TestGetRawTransaction(t *testing.T) {
	block, err := testRest.GetBlockByHeight(0)
	if err != nil {
		t.Errorf("GetBlockByHeight error:%s", err)
		return
	}
	//The first transaction is ont deploy transaction
	ont := block.Transactions[0]
	tx, err := testRest.GetRawTransaction(ont.Hash())
	if err != nil {
		t.Errorf("GetRawTransaction error:%s", err)
		return
	}
	fmt.Printf("TestGetRawTransaction TxHash:%x\n", tx.Hash())
}

func TestGetSmartContract(t *testing.T) {
	block, err := testRest.GetBlockByHeight(0)
	if err != nil {
		t.Errorf("GetBlockByHeight error:%s", err)
		return
	}
	//The first transaction is ont deploy transaction
	ont := block.Transactions[0]
	payload := ont.Payload.(*payload.DeployCode)

	contractAddress := types.AddressFromVmCode(payload.Code)
	contract, err := testRest.GetSmartContract(contractAddress)
	if err != nil {
		t.Errorf("GetSmartContract error:%s", err)
		return
	}
	fmt.Printf("TestGetSmartContract:\n Code:%x\n Author:%s\n Verson:%s\n NeedStorage:%v\n Email:%s\n Description:%s\n",
		contract.Code, contract.Author, contract.Version, contract.NeedStorage, contract.Email, contract.Description)
}

func TestGetGenerateBlockTime(t *testing.T) {
	genTime, err := testRest.GetGenerateBlockTime()
	if err != nil {
		t.Errorf("GetGenerateBlockTime error:%s", err)
		return
	}
	fmt.Printf("TestGetGenerateBlockTime:%d\n", genTime)
}

func TestMerkleProof(t *testing.T) {
	block, err := testRest.GetBlockByHeight(0)
	if err != nil {
		t.Errorf("GetBlockByHeight error:%s", err)
		return
	}
	txHash := block.Transactions[0].Hash()

	proof, err := testRest.GetMerkleProof(txHash)
	if err != nil {
		t.Errorf("GetMerkleProof error:%s", err)
		return
	}
	fmt.Printf("TestMerkleProof %+v\n", proof)
}

func TestDeployContract(t *testing.T) {
	signer, err := testWallet.GetDefaultAccount(testPasswd)
	if err != nil {
		t.Errorf("TestDeployNeoVMContract GetDefaultAccount error:%s\n", err)
		return
	}
	/*
		using Neo.SmartContract.Framework;
		using Neo.SmartContract.Framework.Services.Neo;
		using Neo.SmartContract.Framework.Services.System;
		using System;
		using System.ComponentModel;
		using System.Numerics;
		namespace NeoContract
		{
		   public class Contract1 : SmartContract
		   {
			   public static object Main()
			   {
				   Storage.Put(Storage.CurrentContext, "Hello", "World");
				   return Storage.Get(Storage.CurrentContext, "Hello").AsString();
			   }
		   }
		}
	*/
	//contractCode was compiled by compiler
	contractCode := "51c56b616168164e656f2e53746f726167652e476574436f6e746578740548656c6c6f05576f726c64615272680f4e656f" +
		"2e53746f726167652e507574616168164e656f2e53746f726167652e476574436f6e746578740548656c6c6f617c680f4e656f2e53746f" +
		"726167652e4765746c766b00527ac46203006c766b00c3616c7566"

	txHash, err := testRest.DeploySmartContract(
		0, 50000,
		signer,
		true,
		contractCode,
		"TestDeploySmartContract",
		"1.0",
		"",
		"",
		"",
	)

	if err != nil {
		t.Errorf("TestDeployContract DeploySmartContract error:%s\n", err)
		return
	}
	//WaitForGenerateBlock, ensure contract was be deploy in block
	_, err = testRest.WaitForGenerateBlock(30*time.Second, 1)
	if err != nil {
		t.Errorf("TestDeploySmartContract WaitForGenerateBlock error:%s", err)
		return
	}
	fmt.Printf("TestDeployContract TxHash:%x\n", txHash)
}

func TestInvokeNeoVMContract(t *testing.T) {
	//contractCode was compiled by compiler
	contractCode := "51c56b616168164e656f2e53746f726167652e476574436f6e746578740548656c6c6f05576f726c64615272680f4e656f" +
		"2e53746f726167652e507574616168164e656f2e53746f726167652e476574436f6e746578740548656c6c6f617c680f4e656f2e53746f" +
		"726167652e4765746c766b00527ac46203006c766b00c3616c7566"
	contractCodeAddress, err := utils.GetContractAddress(contractCode)
	if err != nil {
		t.Errorf("GetAssetAddress error:%s", err)
		return
	}
	signer, err := testWallet.GetDefaultAccount(testPasswd)
	if err != nil {
		t.Errorf("TestInvokeNeoVMContract GetDefaultAccount error:%s", err)
		return
	}

	txHash, err := testRest.InvokeNeoVMContract(0, 0, signer, contractCodeAddress, []interface{}{})
	if err != nil {
		t.Errorf("TestInvokeNeoVMContract InvokeNeoVMContract error:%s", err)
		return
	}

	fmt.Printf("TestInvokeNeoVMContract TxHash:%x\n", txHash)
}

func TestPrepareInvokeNativeContract(t *testing.T) {
	result, err := testRest.PrepareInvokeNativeContract(nvutils.OntContractAddress, 0, "name", nil)
	if err != nil {
		t.Errorf("PrepareInvokeNativeContract error:%s", err)
		return
	}
	fmt.Printf("%s\n", result.Result)
}
