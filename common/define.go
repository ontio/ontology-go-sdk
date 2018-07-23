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
//Some common define of ontology-go-sdk
package common

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/ontio/ontology/common"
	"github.com/ontio/ontology/core/payload"
	"math/big"
)

var (
	VERSION_TRANSACTION = byte(0)
)

const (
	WS_SUBSCRIBE_ACTION_BLOCK         = "Block"
	WS_SUBSCRIBE_ACTION_EVENT_NOTIFY  = "Notify"
	WS_SUBSCRIBE_ACTION_EVENT_LOG     = "Log"
	WS_SUBSCRIBE_ACTION_BLOCK_TX_HASH = "BlockTxHash"
)

//Balance object for account
type Balance struct {
	Ont uint64
	Ong uint64
}

//BalanceRsp response object for balance request
type BalanceRsp struct {
	Ont string `json:"ont"`
	Ong string `json:"ong"`
}

type SmartContract payload.DeployCode

type PreExecResult struct {
	State  byte
	Gas    uint64
	Result *ResultItem
}

func (this *PreExecResult) UnmarshalJSON(data []byte) (err error) {
	var state byte
	var gas uint64
	var resultItem *ResultItem
	defer func() {
		if err == nil {
			this.State = state
			this.Gas = gas
			this.Result = resultItem
		}
	}()

	objects := make(map[string]interface{})
	err = json.Unmarshal(data, &objects)
	if err != nil {
		return err
	}
	stateField, ok := objects["State"].(float64)
	if !ok {
		err = fmt.Errorf("Parse State field failed, type error")
		return
	}
	state = byte(stateField)

	gasField, ok := objects["Gas"].(float64)
	if !ok {
		err = fmt.Errorf("Parse Gas field failed, type error")
		return
	}
	gas = uint64(gasField)
	resultField, ok := objects["Result"]
	if !ok {
		return nil
	}
	resultItem = &ResultItem{}
	value, ok := resultField.(string)
	if ok {
		resultItem.value = value
		return nil
	}
	values, ok := resultField.([]interface{})
	if !ok {
		err = fmt.Errorf("Parse Result field, type error")
		return
	}
	resultItem.values = values
	return nil
}

type ResultItem struct {
	value  string
	values []interface{}
}

func (this *ResultItem) ToArray() ([]*ResultItem, error) {
	if this.values == nil {
		return nil, fmt.Errorf("type error")
	}
	items := make([]*ResultItem, 0)
	for _, res := range this.values {
		item := &ResultItem{}
		value, ok := res.(string)
		if ok {
			item.value = value
			items = append(items, item)
			continue
		}
		values, ok := res.([]interface{})
		if !ok {
			return nil, fmt.Errorf("parse items:%v failed, type error", res)
		}
		item.values = values
		items = append(items, item)
	}
	return items, nil
}

func (this ResultItem) ToBool() (bool, error) {
	if this.values != nil {
		return false, fmt.Errorf("type error")
	}
	return this.value == "01", nil
}

func (this ResultItem) ToInteger() (*big.Int, error) {
	data, err := this.ToByteArray()
	if err != nil {
		return nil, err
	}
	return common.BigIntFromNeoBytes(data), nil
}

func (this ResultItem) ToByteArray() ([]byte, error) {
	if this.values != nil {
		return nil, fmt.Errorf("type error")
	}
	return hex.DecodeString(this.value)
}

func (this ResultItem) ToString() (string, error) {
	data, err := this.ToByteArray()
	if err != nil {
		return "", err
	}
	return string(data), nil
}

//SmartContactEvent object for event of transaction
type SmartContactEvent struct {
	TxHash      string
	State       byte
	GasConsumed uint64
	Notify      []*NotifyEventInfo
}

type NotifyEventInfo struct {
	ContractAddress string
	States          interface{}
}

type SmartContractEventLog struct {
	TxHash          string
	ContractAddress string
	Message         string
}

//MerkleProof return struct
type MerkleProof struct {
	Type             string
	TransactionsRoot string
	BlockHeight      uint32
	CurBlockRoot     string
	CurBlockHeight   uint32
	TargetHashes     []string
}

type BlockTxHashes struct {
	Hash         common.Uint256
	Height       uint32
	Transactions []common.Uint256
}

type BlockTxHashesStr struct {
	Hash         string
	Height       uint32
	Transactions []string
}

type MemPoolTxState struct {
	State []*MemPoolTxStateItem
}

type MemPoolTxStateItem struct {
	Height  uint32
	Type    int
	ErrCode int
}

type MemPoolTxCount struct {
	Verified uint32
	Verifing uint32
}
