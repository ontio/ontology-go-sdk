package oni

type State uint8

const (
	STATE_ABNOMAL State = iota
	STATE_NORMAL
)

const (
	URL_NETWORK_STATE   = "/api/v1/network/state"
	URL_CURRENT_HEIGHT  = "/api/v1/block/height"
	URL_VERSION         = "/api/v1/version"
	URL_CHAIN_ID_LIST   = "/api/v1/chainid/list" // TODO: unimplemented
	URL_SWITCH_CHAIN_ID = "/api/v1/chainid/switch"
	URL_CHAIN_ID        = "/api/v1/chainid"
)

type NetworkState struct {
	HostAddr  string
	State     uint8
	UpdatedAt uint32
}

type NetworkStateResp struct {
	Chain        *NetworkState
	DNS          *NetworkState
	DspProxy     *NetworkState
	ChannelProxy *NetworkState
}

type SwitchChainIdReq struct {
	ChainId string
	Config  string
}

type ChainIdResp struct {
	ChainId string
}
