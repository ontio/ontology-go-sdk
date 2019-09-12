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
package types

import (
	"fmt"
	"github.com/ontio/ontology-go-sdk/common"
)

type Transaction interface {
	Transfer(req *TransferReq) (txHash string, err error)
	GetTxRecords(base58Addr string, transferType TxType, asset string, limit uint64,
		height *uint64, skipTxCountFromBlock *string) (GetTxRecordsResp, error) // height and skipTxCountFromBlock could be nil
	GetSCEventByTxHash(txHash string) (*common.SmartContactEvent, error)       // return tx event
	GetSCEventByHeight(height uint64) ([]*common.SmartContactEvent, error)       // return  total event of every tx at block
	PreExecSmartContract(req *PreExecTxReq) (*PreExecTxResp, error)
	InvokeSmartContract(req *InvokeSmartContractReq) (*InvokeSmartContractResp, error)
}

type TxType uint8

const (
	TX_TYPE_ALL TxType = iota
	TX_TYPE_OUT
	TX_TYPE_IN
)

const (
	URL_TRANSFER           = "/api/v1/asset/transfer/direct"
	URL_TX_RECORDS         = "/api/v1/transactions/%s/%d"
	URL_SC_EVENT_BY_TXHASH = "/api/v1/smartcode/event/txhash/%s"
	URL_SC_EVENT_BY_HEIGHT = "/api/v1/smartcode/event/transactions/%d"
	URL_PRE_EXEC_TX        = "/api/v1/smartcontract/preexec"
	URL_INVOKE_SC          = "/api/v1/smartcontract/invoke"
)

type TransferReq struct {
	To       string
	Asset    string
	Amount   string
	Password string
}

type TxRecord struct {
	Txid         string
	Type         TransferType
	From         string
	To           string
	Amount       uint64
	AmountFormat string
	FeeFormat    string
	Asset        string
	Timestamp    uint32
	BlockHeight  uint64
}

type GetTxRecordsResp []*TxRecord

type PreExecTxReq struct {
	Version  string // should be hex string of number, example: 00, 01
	Contract string // base58 address of contract
	Method   string // contract method name
	Params   []interface{}
}

type PreExecTxResp struct {
	Data string
}

type InvokeSmartContractReq struct {
	PreExecTxReq
	Password string
}

type InvokeSmartContractResp struct {
	Tx string
}

func GenTxRecordsUrl(bas58Addr string, txType TxType) string {
	return fmt.Sprintf(URL_TX_RECORDS, bas58Addr, txType)
}

func GenSCEventByTxHashUrl(hash string) string {
	return fmt.Sprintf(URL_SC_EVENT_BY_TXHASH, hash)
}

func GenSCEventByHeightUrl(height uint64) string {
	return fmt.Sprintf(URL_SC_EVENT_BY_HEIGHT, height)
}
