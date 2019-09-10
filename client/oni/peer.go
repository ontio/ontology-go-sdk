package oni

type PeerMgr interface {
	ReconnectPeer(req ReconnectPeerReq) (ReconnectPeerResp, error)
	GetAllDns() (GetAllDNSResp, error)
	GetNodesInfo() (GetNodesInfoResp, error)
}

const (
	URL_RECONNECT_PEER = "/api/v1/network/channel/reconnect"
	URL_GET_ALL_DNS    = "/api/v1/dns"
	URL_GET_NODES_INFO = "/api/v1/dsp/nodes/info"
)

type ReconnectPeerReq struct {
	Peers []string
}

type ReconnectPeerResp struct {
	Peers []*Node
}

type DNS struct {
	HostAddr   string
	WalletAddr string
}

type GetAllDNSResp []*DNS

type GetNodesInfoResp struct {
	Count uint64 // number of registered storage node at network
}
