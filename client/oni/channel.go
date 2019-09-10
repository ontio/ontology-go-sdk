package oni

type ChannelMgr interface {
	CurrentChannel() (*CurrentChannelResp, error)
	SwitchChannel(req *SwitchChannelReq) error
	ChannelIsSyncing() (bool, error)
	ChannelInitProgress() (*ChannelInitProgressResp, error)
	OpenChannel(req *OpenChannelReq) error
	CloseChannel(req *CloseChannelReq) error
	WithdrawChannel(req *WithdrawChannelReq) error
	DepositChannel(req *DepositChannelReq) error
	GetAllChannels() (*GetAllChannelsResp, error)
}

const (
	URL_CURRENT_CHANNEL       = "/api/v1/channel/current"
	URL_SWITCH_CHANNEL        = "/api/v1/channel/switch"
	URL_CHANNEL_IS_SYNCING    = "/api/v1/channel/syncing"
	URL_CHANNEL_INIT_PROGRESS = "/api/v1/channel/init/progress"
	URL_OPEN_CHANNEL          = "/api/v1/channel/open"
	URL_CLOSE_CHANNEL         = "/api/v1/channel/close"
	URL_WITHDRAW_CHANNEL      = "/api/v1/channel/withdraw"
	URL_DEPOSIT_CHANNEL       = "/api/v1/channel/deposit"
	URL_GET_ALL_CHANNELS      = "/api/v1/channel"
)

type Channel struct {
	ChannelId         uint32
	Balance           uint64
	BalanceFormat     string
	Address           string
	HostAddr          string
	TokenAddr         string
	Participant1State uint8 // 0: closing or closed, 1: open
	Participant2State uint8 // 0: closed, 1: open
	IsOnline          bool
	IsDNS             bool
	Connected         bool
	Selected          bool
}

type CurrentChannelResp struct {
	Channel
}

type SwitchChannelReq struct {
	Partner  string
	Password string
}

type ChannelIsSyncingResp struct {
	Syncing bool
}

type ChannelInitProgressResp struct {
	Progress float64
	Start    uint64 // sync-started block
	End      uint64 // sync-ended block
	Now      uint64 // current block
}

type OpenChannelReq struct {
	SwitchChannelReq
	Amount string
}

type CloseChannelReq struct {
	OpenChannelReq
}

type WithdrawChannelReq struct {
	OpenChannelReq
}

type DepositChannelReq struct {
	OpenChannelReq
}

type GetAllChannelsResp struct {
	Balance       uint64
	BalanceFormat string
	Channels      []*Channel
}
