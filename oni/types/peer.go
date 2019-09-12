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

type PeerMgr interface {
	ReconnectPeer(req *ReconnectPeerReq) (*ReconnectPeerResp, error)
	GetAllDns() (*GetAllDNSResp, error)
	GetNodesInfo() (*GetNodesInfoResp, error)
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
