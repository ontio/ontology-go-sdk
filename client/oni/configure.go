package oni

type Configure interface {
	UpdateConfig(req *UpdateConfigReq) error
}

const (
	URL_UPDATE_CONFIG = "/api/v1/config"
)

type UpdateConfigReq struct {
	DownloadPath string
}
