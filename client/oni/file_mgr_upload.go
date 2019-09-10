package oni

import "fmt"

type FileMgrUpload interface {
	CommitUploadTask(req CommitUploadTaskReq) (CommitUploadTaskResp, error)
	UploadPause(req UploadPauseReq) (UploadPauseResp, error)
	UploadResume(req UploadResumeReq) (UploadResumeResp, error)
	UploadFailedRetry(req UploadFailedRetryReq) (UploadFailedRetryResp, error)
	UploadCancel(req UploadCancelReq) (UploadCancelResp, error)
	UpdateFileWhiteList(req UpdateFileWhiteListReq) (UpdateFileWhiteListReq, error)
	GetUploadFileInfo(fileHash string) (GetUploadFileInfoResp, error)
	GetFSSetting() (GetFileStorageSettingResp, error)
	GetFileWhiteList(fileHash string) ([]*WhiteListAddress, error)
	GetUploadFileList(fileType FileType, offset, limit uint64) (GetUploadFileListResp, error)
	GetUploadFileFee(filePath string, duration, proveInterval, copyNum, whiteListCount uint32,
		storeType StorageType) (GetUploadFileFeeResp, error)
}

type FilePrivilege uint8

const (
	FILE_PRIVILEGE_PRIVATE FilePrivilege = iota
	FILE_PRIVILEGE_PUBLIC
	FILE_PRIVILEGE_WHITE_LIST
)

type WhiteListOperator uint8

const (
	WHITE_LIST_OPERATE_REPLACE WhiteListOperator = iota
	WHITE_LIST_OPERATE_DELETE
)

const (
	URL_COMMIT_UPLOAD_TASK       = "/api/v1/dsp/file/upload"
	URL_UPLOAD_PAUSE             = "/api/v1/dsp/file/upload/pause"
	URL_UPLOAD_RESUME            = "/api/v1/dsp/file/upload/resume"
	URL_UPLOAD_FIALED_RETRY      = "/api/v1/dsp/file/upload/retry"
	URL_UPLOAD_CANCEL            = "/api/v1/dsp/file/upload/cancel"
	URL_UPDATE_FILE_WHITE_LIST   = "/api/v1/dsp/file/updatewhitelist"
	URL_GET_UPLOAD_FILE_INFO     = "/api/v1/dsp/file/upload/info/%s"
	URL_GET_FILE_STORAGE_SETTING = "/api/v1/smartcontract/fs/setting"
	URL_GET_FILE_WHITE_LIST      = "/api/v1/dsp/file/whitelist/%s"
	URL_GET_UPLOAD_FILE_LIST     = "/api/v1/dsp/file/uploadlist/%d/%d/%d"
	URL_GET_UPLOAD_FILE_FEE      = "/api/v1/dsp/file/uploadfee/%s" // hex encoded of file absolute path
)

type CommitUploadTaskReq struct {
	Path            string // absolute file path at sync node
	Desc            string // file description
	Interval        uint32 // file existing prove interval, uints second
	Privilege       FilePrivilege
	CopyNum         uint32
	EncryptPassword string
	Url             string // could be specified file share url, may be nil
	// hex string address["0x7f8051d4bf3d5f6edb3971aa7ad113a3b13f7277",
	// "0x7f8051d4bf3d5f6edb3971aa7ad113a3b13f7277"]
	WhiteList []string
	Duration  uint64 // storage duration, if StoreType == STORE_TYPE_NORMAL and Duration == 0, storage until user space expired
	Share     bool   // enable file share or not
	StoreType StorageType
}

type WhiteListAddress struct {
	Addr          string // base58 address
	StartHeight   uint64
	ExpiredHeight uint64
}

type CommitUploadTaskResp struct {
	CopyNum         uint32
	Encrypt         bool
	EncryptPassword string
	ExpiredHeight   uint64
	FileName        string
	FileSize        uint64
	Privilege       FilePrivilege
	ProveInterval   uint32
	Share           bool
	StorageType     StorageType
	Url             string
	WhiteList       []*WhiteListAddress
}

type UploadPauseReq struct {
	Ids []string
}

type UploadPauseResp struct {
	Tasks []*Task
}

type UploadResumeReq struct {
	UploadPauseReq
}

type UploadResumeResp struct {
	UploadPauseResp
}

type UploadFailedRetryReq struct {
	UploadPauseReq
}

type UploadFailedRetryResp struct {
	UploadPauseResp
}

type UploadCancelReq struct {
	UploadPauseReq
	Password string
}

type UploadCancelResp struct {
	UploadPauseResp
}

type UpdateFileWhiteListReq struct {
	FileHash  string
	Operation WhiteListOperator
	List      []*WhiteListAddress
}

type GetUploadFileInfoResp struct {
	FileHash   string
	CreatedAt  uint32
	CopyNum    uint32
	Interval   uint32
	ProveTimes uint32
	Privilege  FilePrivilege
	Whitelist  []*WhiteListAddress
	ExpiredAt  uint32
}

type GetFileStorageSettingResp struct {
	DefaultCopyNum     uint32
	DefaultProvePeriod uint32
	MinChallengeRate   uint32 // min prove times
	MinVolume          uint64 // min storage volume that node provide
}

type UploadFileInfo struct {
	Hash          string
	Name          string
	Url           string
	Size          uint64 // file storage size
	DownloadCount uint64
	ExpiredAt     uint32
	UpdatedAt     uint32 // file modification time, current always return 0
	Profit        uint64
	Privilege     FilePrivilege
	CurrentHeight uint64
	ExpiredHeight uint64
	StoreType     StorageType
	RealFileSize  uint64 // file real size
}

type GetUploadFileListResp []*UploadFileInfo

type GetUploadFileFeeResp struct {
	TxFee            uint64
	TxFeeFormat      string
	StorageFee       uint64
	StorageFeeFormat string
	ValidFee         uint64
	ValidFeeFormat   string
}

func GenGetUploadFileInfoUrl(fileHash string) string {
	return fmt.Sprintf(URL_GET_UPLOAD_FILE_INFO, fileHash)
}

func GenGetFileWhiteListUrl(fileHash string) string {
	return fmt.Sprintf(URL_GET_FILE_WHITE_LIST, fileHash)
}

func GenGetUploadFileListUrl(fileType FileType, offset, limit uint64) string {
	return fmt.Sprintf(URL_GET_UPLOAD_FILE_LIST, fileType, offset, limit)
}

func GenGetUploadFileFeeUrl(hexFilePath string) string {
	return fmt.Sprintf(URL_GET_UPLOAD_FILE_FEE, hexFilePath)
}
