package oni

const (
	URL_CURRENT_CHANNEL       = "/api/v1/channel/current"
	URL_SWITCH_CHANNEL        = "/api/v1/channel/switch"
	URL_CHANNEL_IS_SYNCING    = "/api/v1/channel/syncing"
	URL_CHANNEL_INIT_PROGRESS = "/api/v1/channel/init/progress"
)

type Channel struct {
	ChannelId         uint32
	Balance           uint64
	BalanceFormat     string
	Address           string
	HostAddr          string
	TokenAddr         string
	Participant1State uint8
	Participant2State uint8
	IsDNS             bool
	Connected         bool
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
