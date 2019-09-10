package oni

import "fmt"

type FileMgrTransfer interface {
	GetTransferList(transferType TransferType, offset, limit uint64) (*GetTransferListResp, error)
	GetTransferDetail(transferType TransferType, transferId string) (*GetTransferDetailResp, error)
	DeleteCompleteTask(req *DeleteCompleteTaskReq) (*DeleteCompleteTaskResp, error)
}

type TransferType uint8

const (
	TRANSFER_TYPE_COMPLETING TransferType = iota
	TRANSFER_TYPE_UPLOADING
	TRANSFER_TYPE_DOWNLOADING
)

type TransferStatus uint8

const (
	TRANSFER_STATUS_PAUSE TransferStatus = iota
	TRANSFER_STATUS_PREPARING
	TRANSFER_STATUS_ONGOING
	TRANSFER_STATUS_ABNOMAL
	TRANSFER_STATUS_CANCEL
)

type TransferDetailStatus uint8

const (
	TRAN_DETAIL_STATUS_NONE TransferDetailStatus = iota
	TRAN_DETAIL_STATUS_PAUSE
	TRAN_DETAIL_STATUS_RESUME
	TRAN_DETAIL_STATUS_START_SHARD
	TRAN_DETAIL_STATUS_SHARD_COMPLETE
	TRAN_DETAIL_STATUS_PAY_TO_CHAIN
	TRAN_DETAIL_STATUS_COMPLETE_PAY_TO_CHAIN
	TRAN_DETAIL_STATUS_SUBMIT_WHITE_LIST
	TRAN_DETAIL_STATUS_COMPLETE_SUBMIT_WHITE_LIST
	TRAN_DETAIL_STATUS_FINDING_STORE_NODE
	TRAN_DETAIL_STATUS_FOUND_STORE_NODE
	TRAN_DETAIL_STATUS_PDP_PROVE
	TRAN_DETAIL_STATUS_START_TRANSFER
	TRAN_DETAIL_STATUS_COMPLETE_TRANSFER
	TRAN_DETAIL_STATUS_WAIT_PDP
	TRAN_DETAIL_STATUS_SUBMITED_PDP
	TRAN_DETAIL_STATUS_REGISTER_TO_DNS
	TRAN_DETAIL_STATUS_COMPLETE_REGISTER
	TRAN_DETAIL_STATUS_START_DOWNLOAD
	TRAN_DETAIL_STATUS_DOWNLOADING
	TRAN_DETAIL_STATUS_DOWNLOADED
)

type StorageType uint8

const (
	STORE_TYPE_NORMAL StorageType = iota
	STORE_TYPE_ADVANCED
)

const (
	URL_GET_TRANSFER_LIST    = "/api/v1/dsp/file/transferlist/%d/%d/%d"
	URL_GET_TRANSFER_DETAIL  = "/api/v1/dsp/file/transfer/detail/%d/%s"
	URL_DELETE_COMPLETE_TASK = "/api/v1/dsp/file/transferlist/delete"
)

type UploadResult struct {
	AddWhiteListTx string
	BindDnsTx      string
	FileHash       string
	Link           string
	RegisterDnsTx  string
	Tx             string // pay storage tx hash
	Url            string
}

type Transfer struct {
	GetTransferDetailResp
	Result *UploadResult
}

type GetTransferListResp struct {
	IsTransfering bool
	Transfers     []*Transfer
}

type GetTransferDetailResp struct {
	Id             string // task id
	FileHash       string
	FileName       string
	Type           TransferType
	Status         TransferStatus
	DetailStatus   TransferDetailStatus
	CopyNum        uint32 // number of backups
	Path           string
	IsUploadAction bool // upload is true, download is false
	// file total uploaded size(uints KB), notes: uploading file is redundant backup，so that UploadSize = FileSize * Nodes.length
	// represents the completion of the upload。 And  progress = UploadSize / (FileSize * Nodes.length)
	UploadSize   uint64
	DownloadSize uint64 // file total download size(uints KB),  progress = DownloadSize / FileSize
	FileSize     uint64 // file size(uints KB), while status = 1, file size is 0
	Nodes        []*Node
	Progress     uint8
	CreatedAt    uint32 // task create time
	UpdatedAt    uint32 // task update time
	ErrorCode    uint32
	StoreType    StorageType
	Encrypted    bool
}

type DeleteCompleteTaskReq struct {
	Ids []string
}

type TaskResult struct {
	Tx    string
	Nodes []*Node
}

type Task struct {
	Id     string
	State  TransferStatus
	Result *TaskResult
	Code   uint32
	Error  string
}

type DeleteCompleteTaskResp []*Task

// offset and limit equal 0 represents all data
func GenGetTransferListUrl(transferType TransferType, offset, limit uint64) string {
	return fmt.Sprintf(URL_GET_TRANSFER_LIST, transferType, offset, limit)
}

func GenGetTransferDetailUrl(transferType TransferType, hexId string) string {
	return fmt.Sprintf(URL_GET_TRANSFER_DETAIL, transferType, hexId)
}
