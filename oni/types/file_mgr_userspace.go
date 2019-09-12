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

import "fmt"

type FileMgrUserSpace interface {
	SetUserSpace(req *SetUserSpaceReq) (*SetUserSpaceResp, error)
	CostSetUserSpace(req *CostSetUserSpaceReq) (*CostSetUserSpaceResp, error)
	GetUserSpace(base58Addr string) (*GetUserSpaceResp, error)
	GetUserSpaceRecords(base58Addr string, offset, limit uint64) (*GetUserSpaceRecordsResp, error)
}

type OperationType uint8

const (
	OPERATION_NO_CHANGE OperationType = 0
	OPERATION_INCREASE  OperationType = 1
	OPERATION_REVOKE    OperationType = 2
)

const (
	URL_SET_USER_SPACE         = "/api/v1/dsp/client/userspace/set"
	URL_COST_SET_USER_SPACE    = "/api/v1/dsp/client/userspace/cost"
	URL_GET_USER_SPACE         = "/api/v1/dsp/client/userspace/%s"
	URL_GET_USER_SPACE_RECORDS = "/api/v1/dsp/client/userspacerecords/%s/%d/%d"
)

type Operation struct {
	Type  OperationType
	Value uint64
}

type SetUserSpaceReq struct {
	CostSetUserSpaceReq
	Password string
}

type SetUserSpaceResp struct {
	Tx string
}

type CostSetUserSpaceReq struct {
	Addr   string
	Size   *Operation
	Second *Operation
}

type CostSetUserSpaceResp struct {
	Fee          uint64
	FeeFormat    string
	TransferType TxType
}

type GetUserSpaceResp struct {
	Used          uint64
	Remain        uint64
	ExpiredAt     uint32
	Balance       uint64
	CurrentHeight uint64
	ExpiredHeight uint64
}

type UserSpaceRecord struct {
	Size       uint64
	ExpiredAt  uint32
	Cost       uint64
	CostFormat string
}

type GetUserSpaceRecordsResp struct {
	Records []*UserSpaceRecord
}

func GenGetUserSpaceUrl(base58Addr string) string {
	return fmt.Sprintf(URL_GET_USER_SPACE, base58Addr)
}

// offset and limit equal 0 represents all data
func GenGetUserSpaceRecordsUrl(base58Addr string, offset, limit uint64) string {
	return fmt.Sprintf(URL_GET_USER_SPACE_RECORDS, base58Addr, offset, limit)
}
