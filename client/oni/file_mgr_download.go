package oni

import "fmt"

type FileMgrDownload interface {
	CommitDownloadTask(req *CommitDownloadTaskReq) error
	DownloadPause(req *DownloadPauseReq) (*DownloadPauseResp, error)
	DownloadResume(req *DownloadResumeReq) (*DownloadResumeResp, error)
	DownloadFailedRetry(req *DownloadFailedRetryReq) (*DownloadFailedRetryResp, error)
	DownloadCancel(req *DownloadCancelReq) (*DownloadCancelResp, error)
	GetDownloadInfo(url string) (*GetDownloadInfoResp, error)
	GetDownloadFileList(fileType FileType, offset, limit uint64) (*GetDownloadListResp, error)
}

type FileType uint8

const (
	FILE_TYPE_ALL FileType = iota
	FILE_TYPE_IMAGE
	FILE_TYPE_DOCUMENTS
	FILE_TYPE_VIDEO
	FILE_TYPE_AUDIO
)

const (
	URL_COMMIT_DOWNLOAD_TASK   = "/api/v1/dsp/file/download"
	URL_DOWNLOAD_PAUSE         = "/api/v1/dsp/file/download/pause"
	URL_DOWNLOAD_RESUME        = "/api/v1/dsp/file/download/resume"
	URL_DOWNLOAD_FAILED_RETRY  = "/api/v1/dsp/file/download/retry"
	URL_DOWNLOAD_CANCEL        = "/api/v1/dsp/file/download/cancel"
	URL_GET_DOWNLOAD_INFO      = "/api/v1/dsp/file/downloadinfo/%s"
	URL_GET_DOWNLOAD_FILE_LIST = "/api/v1/dsp/file/downloadlist/%d/%d/%d"
)

type CommitDownloadTaskReq struct {
	Hash        string
	Url         string
	Link        string
	Password    string // decrypt password, not account password
	MaxPeerNum  uint32
	SetFileName bool
}

type DownloadPauseReq struct {
	Ids []string
}

type DownloadPauseResp struct {
	Tasks []*Task
}

type DownloadResumeReq struct {
	DownloadPauseReq
}

type DownloadResumeResp struct {
	DownloadPauseResp
}

type DownloadFailedRetryReq struct {
	DownloadPauseReq
}

type DownloadFailedRetryResp struct {
	DownloadPauseResp
}

type DownloadCancelReq struct {
	DownloadPauseReq
}

type DownloadCancelResp struct {
	DownloadPauseResp
}

type GetDownloadInfoResp struct {
	Hash        string
	Name        string // file name
	Ext         string // file type(suffix name)
	Size        uint64
	Fee         uint64
	FeeFormat   string
	Path        string
	DownloadDir string
}

type GetDownloadListResp struct {
	Hash          string
	Name          string
	Size          uint64
	DownloadCount uint64
	DownloadAt    uint32
	LastShareAt   uint32
	Profit        uint64
}

// hexUrl: hex string of file's download url. For example: hex(save://share/14f00b97) = 736176653A2F2F73686172652F3134663030623937
func GenGetDownloadInfoUrl(hexUrl string) string {
	return fmt.Sprintf(URL_GET_DOWNLOAD_INFO, hexUrl)
}

func GenGetDownloadFileListUrl(fileType FileType, offset, limit uint64) string {
	return fmt.Sprintf(URL_GET_DOWNLOAD_FILE_LIST, fileType, offset, limit)
}
