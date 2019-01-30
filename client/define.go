package client

import (
	"encoding/json"
	"github.com/ontio/ontology/core/types"
	"time"
)

type OntologyClient interface {
	getCurrentBlockHeight(qid string) ([]byte, error)
	getCurrentBlockHash(qid string) ([]byte, error)
	getVersion(qid string) ([]byte, error)
	getNetworkId(qid string) ([]byte, error)
	getBlockByHash(qid, hash string) ([]byte, error)
	getBlockByHeight(qid string, height uint32) ([]byte, error)
	getBlockInfoByHeight(qid string, height uint32) ([]byte, error)
	getBlockHash(qid string, height uint32) ([]byte, error)
	getBlockHeightByTxHash(qid, txHash string) ([]byte, error)
	getBlockTxHashesByHeight(qid string, height uint32) ([]byte, error)
	getRawTransaction(qid, txHash string) ([]byte, error)
	getSmartContract(qid, contractAddress string) ([]byte, error)
	getSmartContractEvent(qid, txHash string) ([]byte, error)
	getSmartContractEventByBlock(qid string, blockHeight uint32) ([]byte, error)
	getStorage(qid, contractAddress string, key []byte) ([]byte, error)
	getMerkleProof(qid, txHash string) ([]byte, error)
	getMemPoolTxState(qid, txHash string) ([]byte, error)
	getMemPoolTxCount(qid string) ([]byte, error)
	sendRawTransaction(qid string, tx *types.Transaction, isPreExec bool) ([]byte, error)
	getShardStorage(shardID uint64, qid, contractAddress string, key []byte) ([]byte, error)
}

const (
	RPC_GET_VERSION                 = "getversion"
	RPC_GET_TRANSACTION             = "getrawtransaction"
	RPC_SEND_TRANSACTION            = "sendrawtransaction"
	RPC_GET_BLOCK                   = "getblock"
	RPC_GET_BLOCK_COUNT             = "getblockcount"
	RPC_GET_BLOCK_HASH              = "getblockhash"
	RPC_GET_CURRENT_BLOCK_HASH      = "getbestblockhash"
	RPC_GET_ONT_BALANCE             = "getbalance"
	RPC_GET_SMART_CONTRACT_EVENT    = "getsmartcodeevent"
	RPC_GET_STORAGE                 = "getstorage"
	RPC_GET_SMART_CONTRACT          = "getcontractstate"
	RPC_GET_GENERATE_BLOCK_TIME     = "getgenerateblocktime"
	RPC_GET_MERKLE_PROOF            = "getmerkleproof"
	RPC_GET_NETWORK_ID              = "getnetworkid"
	RPC_GET_MEM_POOL_TX_COUNT       = "getmempooltxcount"
	RPC_GET_MEM_POOL_TX_STATE       = "getmempooltxstate"
	RPC_GET_BLOCK_TX_HASH_BY_HEIGHT = "getblocktxsbyheight"
	RPC_GET_BLOCK_HEIGHT_BY_TX_HASH = "getblockheightbytxhash"
	SEND_EMERGENCY_GOV_REQ          = "sendemergencygovreq"
	GET_BLOCK_ROOT_WITH_NEW_TX_ROOT = "getblockrootwithnewtxroot"
	RPC_GET_SHARD_STORAGE           = "getshardstorage"
)

//JsonRpc version
const JSON_RPC_VERSION = "2.0"

//JsonRpcRequest object in rpc
type JsonRpcRequest struct {
	Version string        `json:"jsonrpc"`
	Id      string        `json:"id"`
	Method  string        `json:"method"`
	Params  []interface{} `json:"params"`
}

//JsonRpcResponse object response for JsonRpcRequest
type JsonRpcResponse struct {
	Id     string          `json:"id"`
	Error  int64           `json:"error"`
	Desc   string          `json:"desc"`
	Result json.RawMessage `json:"result"`
}

const (
	GET_GEN_BLK_TIME      = "/api/v1/node/generateblocktime"
	GET_CONN_COUNT        = "/api/v1/node/connectioncount"
	GET_BLK_TXS_BY_HEIGHT = "/api/v1/block/transactions/height/"
	GET_BLK_BY_HEIGHT     = "/api/v1/block/details/height/"
	GET_BLK_BY_HASH       = "/api/v1/block/details/hash/"
	GET_BLK_HEIGHT        = "/api/v1/block/height"
	GET_BLK_HASH          = "/api/v1/block/hash/"
	GET_TX                = "/api/v1/transaction/"
	GET_STORAGE           = "/api/v1/storage/"
	GET_BALANCE           = "/api/v1/balance/"
	GET_CONTRACT_STATE    = "/api/v1/contract/"
	GET_SMTCOCE_EVT_TXS   = "/api/v1/smartcode/event/transactions/"
	GET_SMTCOCE_EVTS      = "/api/v1/smartcode/event/txhash/"
	GET_BLK_HGT_BY_TXHASH = "/api/v1/block/height/txhash/"
	GET_MERKLE_PROOF      = "/api/v1/merkleproof/"
	GET_GAS_PRICE         = "/api/v1/gasprice"
	GET_ALLOWANCE         = "/api/v1/allowance/"
	GET_UNBOUNDONG        = "/api/v1/unboundong/"
	GET_MEMPOOL_TXCOUNT   = "/api/v1/mempool/txcount"
	GET_MEMPOOL_TXSTATE   = "/api/v1/mempool/txstate/"
	GET_VERSION           = "/api/v1/version"
	GET_NETWORK_ID        = "/api/v1/networkid"
	POST_RAW_TX           = "/api/v1/transaction"
	GET_SHARD_STORAGE     = "/api/v1/shardstorage/"
)

const (
	ACTION_SEND_RAW_TRANSACTION = "sendrawtransaction"
)

const REST_VERSION = "1.0.0"

type RestfulReq struct {
	Action  string
	Version string
	Type    int
	Data    string
}

type RestfulResp struct {
	Action  string          `json:"action"`
	Result  json.RawMessage `json:"result"`
	Error   int64           `json:"error"`
	Desc    string          `json:"desc"`
	Version string          `json:"version"`
}

const (
	WS_VERSION       = "1.0.0"
	WS_ERROR_SUCCESS = 0
)

var (
	WS_RECV_CHAN_SIZE             = 1024
	DEFAULT_REQ_TIMEOUT           = 10 * time.Second
	DEFAULT_WS_HEARTBEAT_INTERVAL = 60 //s
	DEFAULT_WS_HEARTBEAT_TIMEOUT  = DEFAULT_WS_HEARTBEAT_INTERVAL * 5
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

	WS_ACTION_GET_SHARD_STORAGE           = "getshardstorage"

	WS_SUB_ACTION_RAW_BLOCK     = "sendrawblock"
	WS_SUB_ACTION_JSON_BLOCK    = "sendjsonblock"
	WS_SUB_ACTION_BLOCK_TX_HASH = "sendblocktxhashs"
	WS_SUB_ACTION_NOTIFY        = "Notify"
	WS_SUB_ACTION_LOG           = "Log"
)

const (
	WS_SUB_CONTRACT_FILTER = "ContractsFilter"
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
