package types

import "fmt"

type FileMgrUserSpace interface {
	SetUserSpace(req *SetUserSpaceReq) (*SetUserSpaceResp, error)
	CostSetUserSpace(req *CostSetUserSpaceReq) (*CostSetUserSpaceResp, error)
	GetUserSpace(base58Addr string) (*GetUserSpaceResp, error)
	GetUserSpaceRecords(base58Addr string, offset, limit uint64) (*GetUserSpaceRecordsResp, error)
}

type OperationType uint8

const (
	OPERATION_NO_CHANGE OperationType = 0
	OPERATION_INCREASE  OperationType = 1
	OPERATION_REVOKE    OperationType = 2
)

const (
	URL_SET_USER_SPACE         = "/api/v1/dsp/client/userspace/set"
	URL_COST_SET_USER_SPACE    = "/api/v1/dsp/client/userspace/cost"
	URL_GET_USER_SPACE         = "/api/v1/dsp/client/userspace/%s"
	URL_GET_USER_SPACE_RECORDS = "/api/v1/dsp/client/userspacerecords/%s/%d/%d"
)

type Operation struct {
	Type  OperationType
	Value uint64
}

type SetUserSpaceReq struct {
	Addr     string
	Size     Operation
	Second   Operation
	Password string
}

type SetUserSpaceResp struct {
	Tx string
}

type CostSetUserSpaceReq struct {
	SetUserSpaceReq
}

type CostSetUserSpaceResp struct {
	Fee          uint64
	FeeFormat    string
	TransferType TxType
}

type GetUserSpaceResp struct {
	Used          uint64
	Remain        uint64
	ExpiredAt     uint32
	Balance       uint64
	CurrentHeight uint64
	ExpiredHeight uint64
}

type UserSpaceRecord struct {
	Size       uint64
	ExpiredAt  uint32
	Cost       uint64
	CostFormat string
}

type GetUserSpaceRecordsResp struct {
	Records []*UserSpaceRecord
}

func GenGetUserSpaceUrl(base58Addr string) string {
	return fmt.Sprintf(URL_GET_USER_SPACE, base58Addr)
}

// offset and limit equal 0 represents all data
func GenGetUserSpaceRecordsUrl(base58Addr string, offset, limit uint64) string {
	return fmt.Sprintf(URL_GET_USER_SPACE_RECORDS, base58Addr, offset, limit)
}
