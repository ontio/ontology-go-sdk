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
package utils

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	sdkcom "github.com/ontio/ontology-go-sdk/common"
	"github.com/ontio/ontology/common"
	"github.com/ontio/ontology/core/payload"
	"github.com/ontio/ontology/core/types"
	httpcom "github.com/ontio/ontology/http/base/common"
	"github.com/ontio/ontology/smartcontract/service/native/ont"
	"math/big"
	"time"
)

func GetVersion(data []byte) (string, error) {
	version := ""
	err := json.Unmarshal(data, &version)
	if err != nil {
		return "", fmt.Errorf("json.Unmarshal:%s error:%s", data, err)
	}
	return version, nil
}

func GetBlock(data []byte) (*types.Block, error) {
	hexStr := ""
	err := json.Unmarshal(data, &hexStr)
	if err != nil {
		return nil, fmt.Errorf("json.Unmarshal error:%s", err)
	}
	blockData, err := hex.DecodeString(hexStr)
	if err != nil {
		return nil, fmt.Errorf("hex.DecodeString error:%s", err)
	}
	block := &types.Block{}
	buf := bytes.NewBuffer(blockData)
	err = block.Deserialize(buf)
	if err != nil {
		return nil, err
	}
	return block, nil
}

func GetUint32(data []byte) (uint32, error) {
	count := uint32(0)
	err := json.Unmarshal(data, &count)
	if err != nil {
		return 0, fmt.Errorf("json.Unmarshal:%s error:%s", data, err)
	}
	return count, nil
}

func GetUint64(data []byte) (uint64, error) {
	count := uint64(0)
	err := json.Unmarshal(data, &count)
	if err != nil {
		return 0, fmt.Errorf("json.Unmarshal:%s error:%s", data, err)
	}
	return count, nil
}

func GetInt(data []byte) (int, error) {
	integer := 0
	err := json.Unmarshal(data, &integer)
	if err != nil {
		return 0, fmt.Errorf("json.Unmarshal:%s error:%s", data, err)
	}
	return integer, nil
}

func GetUint256(data []byte) (common.Uint256, error) {
	hexHash := ""
	err := json.Unmarshal(data, &hexHash)
	if err != nil {
		return common.Uint256{}, fmt.Errorf("json.Unmarshal hash:%s error:%s", data, err)
	}
	hash, err := common.Uint256FromHexString(hexHash)
	if err != nil {
		return common.Uint256{}, fmt.Errorf("ParseUint256FromHexString:%s error:%s", data, err)
	}
	return hash, nil
}

func GetTransaction(data []byte) (*types.Transaction, error) {
	hexStr := ""
	err := json.Unmarshal(data, &hexStr)
	if err != nil {
		return nil, fmt.Errorf("json.Unmarshal error:%s", err)
	}
	txData, err := hex.DecodeString(hexStr)
	if err != nil {
		return nil, fmt.Errorf("hex.DecodeString error:%s", err)
	}
	buf := bytes.NewBuffer(txData)
	tx := &types.Transaction{}
	err = tx.Deserialize(buf)
	if err != nil {
		return nil, err
	}
	return tx, nil
}

func GetBalance(data []byte) (*sdkcom.Balance, error) {
	balanceRsp := &sdkcom.BalanceRsp{}
	err := json.Unmarshal(data, &balanceRsp)
	if err != nil {
		return nil, fmt.Errorf("json.Unmarshal BalanceRsp:%s error:%s", data, err)
	}
	ont, ok := new(big.Int).SetString(balanceRsp.Ont, 10)
	if !ok {
		return nil, fmt.Errorf("big.Int.SetString ont %s failed", balanceRsp.Ont)
	}
	ong, ok := new(big.Int).SetString(balanceRsp.Ong, 10)
	if !ok {
		return nil, fmt.Errorf("big.Int.SetString ong %s failed", balanceRsp.Ong)
	}
	return &sdkcom.Balance{
		Ont: ont.Uint64(),
		Ong: ong.Uint64(),
	}, nil
}

func GetStorage(data []byte) ([]byte, error) {
	hexData := ""
	err := json.Unmarshal(data, &hexData)
	if err != nil {
		return nil, fmt.Errorf("json.Unmarshal error:%s", err)
	}
	value, err := hex.DecodeString(hexData)
	if err != nil {
		return nil, fmt.Errorf("hex.DecodeString error:%s", err)
	}
	return value, nil
}

func GetSmartContractEvent(data []byte) (*sdkcom.SmartContactEvent, error) {
	event := &sdkcom.SmartContactEvent{}
	err := json.Unmarshal(data, &event)
	if err != nil {
		return nil, fmt.Errorf("json.Unmarshal SmartContactEvent:%s error:%s", data, err)
	}
	return event, nil
}

func GetSmartContractEventLog(data []byte) (*sdkcom.SmartContractEventLog, error) {
	log := &sdkcom.SmartContractEventLog{}
	err := json.Unmarshal(data, &log)
	if err != nil {
		return nil, fmt.Errorf("json.Unmarshal SmartContractEventLog:%s error:%s", data, err)
	}
	return log, nil
}

func GetSmartContactEvents(data []byte) ([]*sdkcom.SmartContactEvent, error) {
	events := make([]*sdkcom.SmartContactEvent, 0)
	err := json.Unmarshal(data, &events)
	if err != nil {
		return nil, fmt.Errorf("json.Unmarshal SmartContactEvent:%s error:%s", data, err)
	}
	return events, nil
}

func GetSmartContract(data []byte) (*payload.DeployCode, error) {
	hexStr := ""
	err := json.Unmarshal(data, &hexStr)
	if err != nil {
		return nil, fmt.Errorf("json.Unmarshal error:%s", err)
	}
	if hexStr == "" {
		return nil, nil
	}
	hexData, err := hex.DecodeString(hexStr)
	if err != nil {
		return nil, fmt.Errorf("hex.DecodeString error:%s", err)
	}
	buf := bytes.NewReader(hexData)
	deploy := &payload.DeployCode{}
	err = deploy.Deserialize(buf)
	if err != nil {
		return nil, err
	}
	return deploy, nil
}

func GetMerkleProof(data []byte) (*sdkcom.MerkleProof, error) {
	proof := &sdkcom.MerkleProof{}
	err := json.Unmarshal(data, proof)
	if err != nil {
		return nil, fmt.Errorf("json.Unmarshal error:%s", err)
	}
	return proof, nil
}

func GetBlockTxHashes(data []byte) (*sdkcom.BlockTxHashes, error) {
	blockTxHashesStr := &sdkcom.BlockTxHashesStr{}
	err := json.Unmarshal(data, &blockTxHashesStr)
	if err != nil {
		return nil, fmt.Errorf("json.Unmarshal")
	}
	blockTxHashes := &sdkcom.BlockTxHashes{}

	blockHash, err := common.Uint256FromHexString(blockTxHashesStr.Hash)
	if err != nil {
		return nil, err
	}
	txHashes := make([]common.Uint256, 0, len(blockTxHashesStr.Transactions))
	for _, txHashStr := range blockTxHashesStr.Transactions {
		txHash, err := common.Uint256FromHexString(txHashStr)
		if err != nil {
			return nil, err
		}
		txHashes = append(txHashes, txHash)
	}
	blockTxHashes.Hash = blockHash
	blockTxHashes.Height = blockTxHashesStr.Height
	blockTxHashes.Transactions = txHashes
	return blockTxHashes, nil
}

func GetMemPoolTxState(data []byte) (*sdkcom.MemPoolTxState, error) {
	txState := &sdkcom.MemPoolTxState{}
	err := json.Unmarshal(data, txState)
	if err != nil {
		return nil, fmt.Errorf("json.Unmarshal error:%s", err)
	}
	return txState, nil
}

func GetMemPoolTxCount(data []byte) (*sdkcom.MemPoolTxCount, error) {
	count := make([]uint32, 0, 2)
	err := json.Unmarshal(data, &count)
	if err != nil {
		return nil, fmt.Errorf("json.Unmarshal error:%s", err)
	}
	if len(count) != 2 {
		return nil, fmt.Errorf("count len != 2")
	}
	return &sdkcom.MemPoolTxCount{
		Verified: count[0],
		Verifing: count[1],
	}, nil
}

func NewNativeInvokeTransaction(gasPrice,
	gasLimit uint64,
	cversion byte,
	contractAddress common.Address,
	method string,
	params []interface{},
) (*types.Transaction, error) {
	if params == nil {
		params = make([]interface{}, 0, 1)
	}
	//Params cannot empty, if params is empty, fulfil with empty string
	if len(params) == 0 {
		params = append(params, "")
	}
	invokeCode, err := httpcom.BuildNativeInvokeCode(contractAddress, cversion, method, params)
	if err != nil {
		return nil, fmt.Errorf("BuildNativeInvokeCode error:%s", err)
	}
	return sdkcom.NewInvokeTransaction(gasPrice, gasLimit, invokeCode), nil
}

func NewNeoVMInvokeTransaction(
	gasPrice, gasLimit uint64,
	contractAddress common.Address,
	params []interface{},
) (*types.Transaction, error) {

	invokeCode, err := httpcom.BuildNeoVMInvokeCode(contractAddress, params)
	if err != nil {
		return nil, err
	}
	return sdkcom.NewInvokeTransaction(gasPrice, gasLimit, invokeCode), nil
}

func NewTransferTransaction(gasPrice, gasLimit uint64, asset string, from, to common.Address, amount uint64) (*types.Transaction, error) {
	var sts []*ont.State
	sts = append(sts, &ont.State{
		From:  from,
		To:    to,
		Value: amount,
	})
	return NewMultiTransferTransaction(gasPrice, gasLimit, asset, sts)
}

func NewMultiTransferTransaction(gasPrice, gasLimit uint64, asset string, states []*ont.State) (*types.Transaction, error) {
	contractAddress, err := GetAssetAddress(asset)
	if err != nil {
		return nil, err
	}
	return NewNativeInvokeTransaction(gasPrice, gasLimit, sdkcom.VERSION_CONTRACT_ONT, contractAddress, sdkcom.NATIVE_TRANSFER, []interface{}{states})
}

func NewApproveTransaction(gasPrice, gasLimit uint64, asset string, from, to common.Address, amount uint64) (*types.Transaction, error) {
	contractAddress, err := GetAssetAddress(asset)
	if err != nil {
		return nil, err
	}
	st := &ont.State{
		From:  from,
		To:    to,
		Value: amount,
	}
	return NewNativeInvokeTransaction(gasPrice, gasLimit, sdkcom.VERSION_CONTRACT_ONT, contractAddress, sdkcom.NATIVE_APPROVE, []interface{}{st})
}

func NewTransferFromTransaction(gasPrice, gasLimit uint64, asset string, sender, from, to common.Address, amount uint64) (*types.Transaction, error) {
	contractAddress, err := GetAssetAddress(asset)
	if err != nil {
		return nil, err
	}
	st := &ont.TransferFrom{
		Sender: sender,
		From:   from,
		To:     to,
		Value:  amount,
	}
	return NewNativeInvokeTransaction(gasPrice, gasLimit, sdkcom.VERSION_CONTRACT_ONT, contractAddress, sdkcom.NATIVE_TRANSFER_FROM, []interface{}{st})
}

//WaitForGenerateBlock Wait ontology generate block. Default wait 2 blocks.
//return timeout error when there is no block generate in some time.
func WaitForGenerateBlock(getBlockHeight func() (uint32, error), timeout time.Duration, blockCount ...uint32) (bool, error) {
	count := uint32(2)
	if len(blockCount) > 0 && blockCount[0] > 0 {
		count = blockCount[0]
	}
	blockHeight, err := getBlockHeight()
	if err != nil {
		return false, fmt.Errorf("GetBlockHeight error:%s", err)
	}
	secs := int(timeout / time.Second)
	if secs <= 0 {
		secs = 1
	}
	for i := 0; i < secs; i++ {
		time.Sleep(time.Second)
		curBlockHeigh, err := getBlockHeight()
		if err != nil {
			continue
		}
		if curBlockHeigh-blockHeight >= count {
			return true, nil
		}
	}
	return false, fmt.Errorf("timeout after %d (s)", secs)
}
