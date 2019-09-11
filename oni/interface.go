package oni

import "github.com/ontio/ontology-go-sdk/oni/types"

type OniClient interface {
	types.AccountMgr
	types.Transaction
	types.FileMgrCrypto
	types.FileMgrDelete
	types.FileMgrUserSpace
	types.FileMgrTransfer
	types.FileMgrDownload
	types.FileMgrUpload
	types.ChannelMgr
	types.Mine
	types.PeerMgr
	types.Configure
	types.Others
}
