/*
 * Copyright (C) 2018 The ontology Authors
 * This file is part of The ontology library.
 *
 * The ontology is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * The ontology is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with The ontology.  If not, see <http://www.gnu.org/licenses/>.
 */
package types

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
	*Channel
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
	SwitchChannelReq
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
