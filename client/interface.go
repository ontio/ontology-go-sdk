package client

import (
	"github.com/ontio/ontology/core/types"
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
}
