package oni

type FileMgrDelete interface {
	DeleteFile(req *DeleteFileReq) (*DeleteFileResp, error)
	DeleteFiles(req *DeleteFilesReq) (*DeleteFilesResp, error)
}

const (
	URL_DELETE_FILE  = "/api/v1/dsp/file/delete"
	URL_DELETE_FILES = "/api/v1/dsp/files/delete"
)

// if uploaded file, delete it from saved node
// if download file, delete it from local
type DeleteFileReq struct {
	Hash string
}

type Node struct {
	HostAddr string
	Code     uint
	Error    string
}

type DeleteFileResp struct {
	Tx         string
	FileHash   string
	FileName   string
	Nodes      []*Node
	IsUploaded bool
}

type DeleteFilesReq struct {
	Hash []string
}

type DeleteFilesResp []DeleteFileResp
