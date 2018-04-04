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
	"fmt"
	"github.com/ontio/ontology-go-sdk/common"
	"github.com/ontio/ontology-go-sdk/utils"
	"github.com/ontio/ontology/core/genesis"
	"github.com/ontio/ontology/smartcontract/service/native"
	"math/big"
	"testing"
)

//RpcClient instance of test only
var testRpc *RpcClient

func init() {
	testRpc = NewRpcClient(common.CRYPTO_SCHEME_DEFAULT)
	testRpc.SetAddress("http://localhost:20336")
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
	genesisHash := "077b1ef80c169098a7421adc4962906e69ba8036e257945cea31125c115ba364"
	blockHash, err := utils.ParseUint256FromHexString(genesisHash)
	if err != nil {
		t.Errorf("TestGetBlockByHash ParseUint256FromHexString error:%s", err)
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
	fmt.Printf("TestGetBalance ONT:%d ONG:%d ONGAppove:%d\n", balance.Ont.Int64(), balance.Ong.Int64(), balance.OngAppove.Int64())
}

func TestGetStorage(t *testing.T) {
	value, err := testRpc.GetStorage(genesis.OntContractAddress, native.TOTAL_SUPPLY_NAME)
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
	//for _, event := range events {
	//	fmt.Printf(" TxHash:%x\n", event.TxHash)
	//	fmt.Printf(" SmartContractAddress:%x\n", event.Address)
	//	name := event.States[0].(string)
	//	from := event.States[1].([]byte)
	//	to := event.States[2].([]byte)
	//	value := event.States[3].(*big.Int)
	//	fmt.Printf(" State Name:%s from:%x to:%x value:%d\n", name, from, to, value.Int64())
	//}
}

func TestGetRawTransaction(t *testing.T) {
	ontInitTxHash := "476a15e30208e84dd5307e4fc3c8c268650e88c1b44f96741053bf63d23cd023"
	ontInitTx, err := utils.ParseUint256FromHexString(ontInitTxHash)
	if err != nil {
		t.Errorf("ParseUint256FromHexString error:%s", err)
		return
	}
	tx, err := testRpc.GetRawTransaction(ontInitTx)
	if err != nil {
		t.Errorf("GetRawTransaction error:%s", err)
		return
	}
	fmt.Printf("TestGetRawTransaction TxHash:%x\n", tx.Hash())
}

func TestGetSmartContract(t *testing.T) {
	smAddress := "ff40227671f2b544a69fd4204a904577a01f428f" //ONT origin address
	addr, err := utils.ParseAddressFromHexString(smAddress)
	if err != nil {
		t.Errorf("TestGetStorage ParseAddressFromHexString error:%s", err)
		return
	}
	contract, err := testRpc.GetSmartContract(addr)
	if err != nil {
		t.Errorf("GetSmartContract error:%s", err)
		return
	}
	fmt.Printf("TestGetSmartContract Code:%x\n Author:%s\n Verson:%s\n NeedStorage:%v\n Email:%s\n Description:%s\n",
		contract.Code.Code, contract.Author, contract.Version, contract.NeedStorage, contract.Email, contract.Description)
}