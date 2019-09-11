package types

type FileMgrCrypto interface {
	Encrypt(req *EncryptFileReq) error
	Decrypt(req *DecryptFileReq) error
}

const (
	URL_ENCRYPT_FILE = "/api/v1/dsp/file/encrypt"
	URL_DECRYPT_FILE = "/api/v1/dsp/file/decrypt"
)

type EncryptFileReq struct {
	Path     string // should be absolute path at sync node(sync instance)
	Password string
}

type DecryptFileReq struct {
	EncryptFileReq
}
