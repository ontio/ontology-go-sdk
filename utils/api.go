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
	"encoding/hex"
	"encoding/json"
	"fmt"
	sdkcom "github.com/ontio/ontology-go-sdk/common"
	"github.com/ontio/ontology/common"
	"github.com/ontio/ontology/core/payload"
	"github.com/ontio/ontology/core/types"
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
	return types.BlockFromRawBytes(blockData)
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
	return types.TransactionFromRawBytes(txData)
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
	source := common.NewZeroCopySource(hexData)
	deploy := &payload.DeployCode{}
	err = deploy.Deserialization(source)
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
