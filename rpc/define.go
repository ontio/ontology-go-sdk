package rpc

import (
	"encoding/json"
)

const (
	RPC_GET_VERSION              = "getversion"
	RPC_GET_TRANSACTION          = "getrawtransaction"
	RPC_SEND_TRANSACTION         = "sendrawtransaction"
	RPC_GET_BLOCK                = "getblock"
	RPC_GET_BLOCK_COUNT          = "getblockcount"
	RPC_GET_BLOCK_HASH           = "getblockhash"
	RPC_GET_CURRENT_BLOCK_HASH   = "getbestblockhash"
	RPC_GET_ONT_BALANCE          = "getbalance"
	RPC_GET_SMART_CONTRACT_EVENT = "getsmartcodeevent"
	RPC_GET_STORAGE              = "getstorage"
	RPC_GET_SMART_CONTRACT       = "getcontractstate"
)

const JSON_RPC_VERSION = "2.0"

type JsonRpcRequest struct {
	Version string        `json:"jsonrpc"`
	Id      string        `json:"id"`
	Method  string        `json:"method"`
	Params  []interface{} `json:"params"`
}

type JsonRpcResponse struct {
	Error  int64           `json:"error"`
	Desc   string          `json:"desc"`
	Result json.RawMessage `json:"result"`
}

type BalanceRsp struct {
	Ont string `json:"ont"`
	Ong string `json:"ong"`
}
