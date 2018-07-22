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
package ws

import (
	"encoding/json"
	"time"
)

const (
	WS_VERSION = "1.0.0"

	WS_ERROR_SUCCESS = 0
)

var (
	WS_RECV_CHAN_SIZE             = 1024
	DEFAULT_REQ_TIMEOUT           = 10 * time.Second
	DEFAULT_WS_HEARTBEAT_INTERVAL = 60 //s
)

const (
	WS_ACTION_HEARBEAT                    = "heartbeat"
	WS_ACTION_SUBSCRIBE                   = "subscribe"
	WS_ACTION_GET_BLOCK_TX_HASH_BY_HEIGHT = "getblocktxsbyheight"
	WS_ACTION_GET_BLOCK_BY_HEIGHT         = "getblockbyheight"
	WS_ACTION_GET_BLOCK_BY_HASH           = "getblockbyhash"
	WS_ACTION_GET_BLOCK_HEIGHT            = "getblockheight"
	WS_ACTION_GET_BLOCK_HASH              = "getblockhash"
	WS_ACTION_GET_TRANSACTION             = "gettransaction"
	WS_ACTION_SEND_TRANSACTION            = "sendrawtransaction"
	WS_ACTION_GET_STORAGE                 = "getstorage"
	WS_ACTION_GET_CONTRACT                = "getcontract"
	WS_ACTION_GET_SMARTCONTRACT_BY_HEIGHT = "getsmartcodeeventbyheight"
	WS_ACTION_GET_SMARTCONTRACT_BY_HASH   = "getsmartcodeeventbyhash"
	WS_ACTION_GET_BLOCK_HEIGHT_BY_TX_HASH = "getblockheightbytxhash"
	WS_ACTION_GET_MERKLE_PROOF            = "getmerkleproof"
	WS_ACTION_GET_GENERATE_BLOCK_TIME     = "getgenerateblocktime"
	WS_ACTION_GET_GAS_PRICE               = "getgasprice"
	WS_ACTION_GET_MEM_POOL_TX_STATE       = "getmempooltxstate"
	WS_ACTION_GET_MEM_POOL_TX_COUNT       = "getmempooltxcount"
	WS_ACTION_GET_VERSION                 = "getversion"
	WS_ACTION_GET_NETWORK_ID              = "getnetworkid"

	WS_SUB_ACTION_RAW_BLOCK     = "sendrawblock"
	WS_SUB_ACTION_JSON_BLOCK    = "sendjsonblock"
	WS_SUB_ACTION_BLOCK_TX_HASH = "sendblocktxhashs"
	WS_SUB_ACTION_NOTIFY        = "Notify"
	WS_SUB_ACTION_LOG           = "Log"
)

const (
	WS_SUBSCRIBE_ACTION_BLOCK         = "Block"
	WS_SUBSCRIBE_ACTION_EVENT_NOTIFY  = "Notify"
	WS_SUBSCRIBE_ACTION_EVENT_LOG     = "Log"
	WS_SUBSCRIBE_ACTION_BLOCK_TX_HASH = "BlockTxHash"
)

const (
	WS_SUB_CONTRACT_FILTER = "ConstractsFilter"
	WS_SUB_EVENT           = "SubscribeEvent"
	WS_SUB_JSON_BLOCK      = "SubscribeJsonBlock"
	WS_SUB_RAW_BLOCK       = "SubscribeRawBlock"
	WS_SUB_BLOCK_TX_HASH   = "SubscribeBlockTxHashs"
)

type WSRequest struct {
	Id     string
	Params map[string]interface{}
	ResCh  chan *WSResponse
}

type WSResponse struct {
	Id      string
	Action  string
	Result  json.RawMessage
	Error   int
	Desc    string
	Version string
}

type WSAction struct {
	Action string
	Result interface{}
}

type WSSubscribeStatus struct {
	ConstractsFilter      []string
	SubscribeEvent        bool
	SubscribeJsonBlock    bool
	SubscribeRawBlock     bool
	SubscribeBlockTxHashs bool
}

func (this *WSSubscribeStatus) GetContractFilter() []string {
	contracts := make([]string, len(this.ConstractsFilter))
	copy(contracts, this.ConstractsFilter)
	return contracts
}

func (this *WSSubscribeStatus) HasContractFilter(contractAddress string) bool {
	for _, address := range this.ConstractsFilter {
		if address == contractAddress {
			return true
		}
	}
	return false
}

func (this *WSSubscribeStatus) AddContractFilter(contractAddress string) {
	if this.ConstractsFilter == nil {
		this.ConstractsFilter = make([]string, 0)
	}
	if this.HasContractFilter(contractAddress) {
		return
	}
	this.ConstractsFilter = append(this.ConstractsFilter, contractAddress)
}

func (this *WSSubscribeStatus) DelContractFilter(contractAddress string) {
	size := len(this.ConstractsFilter)
	if size == 0 {
		return
	}
	for index, address := range this.ConstractsFilter {
		if address == contractAddress {
			if index == size-1 {
				this.ConstractsFilter = this.ConstractsFilter[:index]
			} else {
				this.ConstractsFilter = append(this.ConstractsFilter[:index], this.ConstractsFilter[index+1:]...)
			}
			break
		}
	}
}
