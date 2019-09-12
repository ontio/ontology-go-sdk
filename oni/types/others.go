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

type Others interface {
	NetworkState() (*NetworkStateResp, error)
	CurrentHeight() (uint64, error)
	Version() (string, error)
	ChainIdList() // TODO:
	SwitchChainId(req *SwitchChainIdReq) error
	ChainId() (string, error)
}

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
