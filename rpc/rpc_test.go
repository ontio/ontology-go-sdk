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

package rpc

import (
	"encoding/hex"
	"fmt"
	"github.com/ontio/ontology-crypto/keypair"
	s "github.com/ontio/ontology-crypto/signature"
	"github.com/ontio/ontology-go-sdk/utils"
	"github.com/ontio/ontology/account"
	ontcom "github.com/ontio/ontology/common"
	"github.com/ontio/ontology/core/genesis"
	"github.com/ontio/ontology/core/payload"
	"github.com/ontio/ontology/smartcontract/service/native/ont"
	"github.com/ontio/ontology/smartcontract/types"
	"math/big"
	"os"
	"testing"
	"time"
)

//RpcClient instance of test only
var (
	testRpc    *RpcClient
	testWallet account.Client
	testPasswd = []byte("password")
)

func TestMain(t *testing.M) {
	var err error
	testRpc = NewRpcClient()
	testRpc.SetAddress("http://localhost:20336")
	walletFile := "./wallet.dat"
	testWallet, err = account.Open(walletFile)
	if err != nil {
		fmt.Errorf("wallet open error:%s", err)
		return
	}
	_, err = testWallet.NewAccount("t", keypair.PK_ECDSA, keypair.P256, s.SHA256withECDSA, testPasswd)
	if err != nil {
		fmt.Errorf("NewAccount error:%s", err)
		return
	}
	t.Run()
	os.Remove("./ActorLog")
	os.Remove(walletFile)
}

func TestGetVersion(t *testing.T) {
	v, err := testRpc.GetVersion()
	if err != nil {
		t.Errorf("GetVersion error:%s", err)
		return
	}
	fmt.Printf("TestGetVersion Version:%v\n", v)
}

func TestGetBlockByHash(t *testing.T) {
	blockHash, err := testRpc.GetBlockHash(0)
	if err != nil {
		t.Errorf("GetBlockHash error:%s", err)
		return
	}
	block, err := testRpc.GetBlockByHash(blockHash)
	if err != nil {
		t.Errorf("GetBlockByHash error:%s", err)
		return
	}
	fmt.Printf("TestGetBlockByHash BlockHeight:%d BlockHash:%x\n", block.Header.Height, block.Hash())
}

func TestGetBlockByHeight(t *testing.T) {
	block, err := testRpc.GetBlockByHeight(0)
	if err != nil {
		t.Errorf("GetBlockByHash error:%s", err)
		return
	}
	fmt.Printf("TestGetBlockByHeight BlockHeight:%d BlockHash:%x\n", block.Header.Height, block.Hash())
}

func TestGetBlockCount(t *testing.T) {
	count, err := testRpc.GetBlockCount()
	if err != nil {
		t.Errorf("GetBlockCount error:%s", err)
		return
	}
	fmt.Printf("TestGetBlockCount BlockCount:%d\n", count)
}

func TestGetCurrentBlockHash(t *testing.T) {
	blockHash, err := testRpc.GetCurrentBlockHash()
	if err != nil {
		t.Errorf("GetCurrentBlockHash error:%s", err)
		return
	}
	fmt.Printf("GetCurrentBlockHash %x\n", blockHash)
}

func TestGetBlockHash(t *testing.T) {
	blockHash, err := testRpc.GetBlockHash(0)
	if err != nil {
		t.Errorf("GetBlockHash error:%s", err)
		return
	}
	fmt.Printf("TestGetBlockHash %x\n", blockHash)
}

func TestGetBalance(t *testing.T) {
	address := "TA7KWDW7Bre2Lzpt98FckK9P5Susf1bNTS"
	balance, err := testRpc.GetBalanceWithBase58(address)
	if err != nil {
		t.Errorf("GetBalance error:%s", err)
		return
	}
	fmt.Printf("TestGetBalance ONT:%d ONG:%d ONGAppove:%d\n", balance.Ont, balance.Ong, balance.OngAppove)
}

func TestGetStorage(t *testing.T) {
	value, err := testRpc.GetStorage(genesis.OntContractAddress, ont.TOTAL_SUPPLY_NAME)
	if err != nil {
		t.Errorf("GetStorage error:%s", err)
		return
	}
	totalSupply := new(big.Int).SetBytes(value)
	fmt.Printf("TestGetStorage %d\n", totalSupply.Int64())
}

func TestGetSmartContractEvent(t *testing.T) {
	ontInitTxHash := "476a15e30208e84dd5307e4fc3c8c268650e88c1b44f96741053bf63d23cd023"
	ontInitTx, err := utils.ParseUint256FromHexString(ontInitTxHash)
	if err != nil {
		t.Errorf("TestGetSmartContractEvent ParseUint256FromHexString error:%s", err)
		return
	}
	events, err := testRpc.GetSmartContractEvent(ontInitTx)
	if err != nil {
		t.Errorf("GetSmartContractEvent error:%s", err)
		return
	}

	fmt.Printf("GetSmartContractEvent:%+v\n", events)
	for _, event := range events {
		fmt.Printf(" TxHash:%x\n", event.TxHash)
		fmt.Printf(" SmartContractAddress:%x\n", event.ContractAddress)
		name := event.States[0].(string)
		from := event.States[1].(string)
		to := event.States[2].(string)
		value := event.States[3].(string)
		data, err := hex.DecodeString(value)
		if err != nil {
			t.Errorf("DecodeString error:%s", err)
			return
		}
		v := new(big.Int).SetBytes(data)
		fmt.Printf(" State Name:%s from:%s to:%s value:%d\n", name, from, to, v.Int64())
	}
}

func TestGetRawTransaction(t *testing.T) {
	block, err := testRpc.GetBlockByHeight(0)
	if err != nil {
		t.Errorf("GetBlockByHeight error:%s", err)
		return
	}
	//The first transaction is ont deploy transaction
	ont := block.Transactions[0]
	tx, err := testRpc.GetRawTransaction(ont.Hash())
	if err != nil {
		t.Errorf("GetRawTransaction error:%s", err)
		return
	}
	fmt.Printf("TestGetRawTransaction TxHash:%x\n", tx.Hash())
}

func TestGetSmartContract(t *testing.T) {
	block, err := testRpc.GetBlockByHeight(0)
	if err != nil {
		t.Errorf("GetBlockByHeight error:%s", err)
		return
	}
	//The first transaction is ont deploy transaction
	ont := block.Transactions[0]
	payload := ont.Payload.(*payload.DeployCode)

	//native contract is different with other (neovm or wason)
	//if neovm the address = payload.Code.AddressFromVmCode()
	contractAddress, err := ontcom.AddressParseFromBytes(payload.Code.Code)
	if err != nil {
		t.Errorf("AddressParseFromBytes error:%s", err)
		return
	}
	contract, err := testRpc.GetSmartContract(contractAddress)
	if err != nil {
		t.Errorf("GetSmartContract error:%s", err)
		return
	}
	fmt.Printf("TestGetSmartContract:\n Code:%x\n Author:%s\n Verson:%s\n NeedStorage:%v\n Email:%s\n Description:%s\n",
		contract.Code.Code, contract.Author, contract.Version, contract.NeedStorage, contract.Email, contract.Description)
}

func TestGetGenerateBlockTime(t *testing.T) {
	genTime, err := testRpc.GetGenerateBlockTime()
	if err != nil {
		t.Errorf("GetGenerateBlockTime error:%s", err)
		return
	}
	fmt.Printf("TestGetGenerateBlockTime:%d\n", genTime)
}

func TestMerkleProof(t *testing.T) {
	block, err := testRpc.GetBlockByHeight(0)
	if err != nil {
		t.Errorf("GetBlockByHeight error:%s", err)
		return
	}
	txHash := block.Transactions[0].Hash()

	proof, err := testRpc.GetMerkleProof(txHash)
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
	contractCodeAddress := utils.GetNeoVMContractAddress(contractCode)
	txHash, err := testRpc.DeploySmartContract(
		0, 0,
		signer,
		types.NEOVM,
		true,
		contractCode,
		"TestDeploySmartContract",
		"1.0",
		"",
		"",
		"",
	)

	fmt.Printf("TestDeployContract CodeAddress:%x\n", contractCodeAddress.ToBase58())
	if err != nil {
		t.Errorf("TestDeployContract DeploySmartContract error:%s\n", err)
		return
	}
	//WaitForGenerateBlock, ensure contract was be deploy in block
	_, err = testRpc.WaitForGenerateBlock(30*time.Second, 1)
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
	contractCodeAddress := utils.GetNeoVMContractAddress(contractCode)
	signer, err := testWallet.GetDefaultAccount(testPasswd)
	if err != nil {
		t.Errorf("TestInvokeNeoVMContract GetDefaultAccount error:%s", err)
		return
	}

	txHash, err := testRpc.InvokeNeoVMSmartContract(0, 0, signer, 0, contractCodeAddress, []interface{}{})
	if err != nil {
		t.Errorf("TestInvokeNeoVMContract InvokeNeoVMSmartContract error:%s", err)
		return
	}

	fmt.Printf("TestInvokeNeoVMContract TxHash:%x\n", txHash)
}
