package oni

import "fmt"

type OperationType uint8

const (
	OPERATION_NO_CHANGE OperationType = 0
	OPERATION_INCREASE  OperationType = 1
	OPERATION_REVOKE    OperationType = 2
)

const (
	URL_USER_SPACE_SET         = "/api/v1/dsp/client/userspace/set"
	URL_USER_SPACE_SET_COST    = "/api/v1/dsp/client/userspace/cost"
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

type UserSpaceSetCostReq struct {
	SetUserSpaceReq
}

type UserSpaceSetCostResp struct {
	Fee          uint64
	FeeFormat    string
	TransferType TxType
}

type GetUserSpaceUrlResp struct {
	Used          uint64
	Remain        uint64
	ExpiredAt     uint32
	Balance       uint64
	CurrentHeight uint64
	ExpiredHeight uint64
}

func GenGetUserSpaceUrlWithAddr(base58Addr string) string {
	return fmt.Sprintf(URL_GET_USER_SPACE, base58Addr)
}

// offset and limit equal 0 represents all data
func GenGetUserSpaceRecordsUrl(base58Addr string, offset, limit uint64) string {
	return fmt.Sprintf(URL_GET_USER_SPACE_RECORDS, base58Addr, offset, limit)
}
