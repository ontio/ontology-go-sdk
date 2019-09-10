package oni

import (
	"fmt"
	"github.com/ontio/ontology-go-sdk/common"
)

type Transaction interface {
	Transfer(req TransferReq) (txHash string, err error)
	GetTxRecords(base58Addr string, transferType TransferType, asset string, limit uint64,
		height *uint64, skipTxCountFromBlock *string) (GetTxRecordsResp, error) // height and skipTxCountFromBlock could be nil
	GetSCEventByTxHash(txHash string) ([]*common.SmartContactEvent, error)      // return tx event
	GetSCEventByHeight(height uint64) ([]*common.SmartContactEvent, error)      // return  total event of every tx at block
	PreExecSmartContract(req PreExecTxReq) (PreExecTxResp, error)
	InvokeSmartContract(req InvokeSmartContractReq) (InvokeSmartContractResp, error)
}

type TxType uint8

const (
	TRANSFER_TYPE_ALL TxType = iota
	TRANSFER_TYPE_OUT
	TRANSFER_TYPE_IN
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

func GenTxRecordsUrlWithAddrAndType(bas58Addr string, txType TxType) string {
	return fmt.Sprintf(URL_TX_RECORDS, txType)
}

func GenSCEventByTxHashUrlWithHash(hash string) string {
	return fmt.Sprintf(URL_SC_EVENT_BY_TXHASH, hash)
}

func GenSCEventByHeightUrlWithHeight(height uint64) string {
	return fmt.Sprintf(URL_SC_EVENT_BY_HEIGHT, height)
}
