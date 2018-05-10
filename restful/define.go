package restful

import (
	"encoding/json"
)

const (
	GET_GEN_BLK_TIME      = "/api/v1/node/generateblocktime"
	GET_CONN_COUNT        = "/api/v1/node/connectioncount"
	GET_BLK_TXS_BY_HEIGHT = "/api/v1/block/transactions/height/:height"
	GET_BLK_BY_HEIGHT     = "/api/v1/block/details/height/:height"
	GET_BLK_BY_HASH       = "/api/v1/block/details/hash/:hash"
	GET_BLK_HEIGHT        = "/api/v1/block/height"
	GET_BLK_HASH          = "/api/v1/block/hash/"
	GET_TX                = "/api/v1/transaction/"
	GET_STORAGE           = "/api/v1/storage/:hash/:key"
	GET_BALANCE           = "/api/v1/balance/:addr"
	GET_CONTRACT_STATE    = "/api/v1/contract/"
	GET_SMTCOCE_EVT_TXS   = "/api/v1/smartcode/event/transactions/"
	GET_SMTCOCE_EVTS      = "/api/v1/smartcode/event/txhash/"
	GET_BLK_HGT_BY_TXHASH = "/api/v1/block/height/txhash/"
	POST_RAW_TX          = "/api/v1/transaction"
	GET_MERKLE_PROOF      = "/api/v1/merkleproof/"
)

type RestfulReq struct {
	Action     string      `json:"action"`
	Version    string      `json:"version"`
	Type       int         `json:"type"`
	Data       string      `json:"data"`
}

type RestfulResp struct {
	Action   string           `json:"action"`
	Result   json.RawMessage  `json:"result"`
	Error    int64            `json:"error"`
	Desc     string           `json:"desc"`
	Version  string           `json:"version"`
}


