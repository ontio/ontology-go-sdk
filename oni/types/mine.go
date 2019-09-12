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

type Mine interface {
	Revenue() (*RevenueResp, error)
	MinerGetShardIncome(begin, end uint32, offset, limit uint64) (*MinerGetShardIncomeResp, error)
}

const (
	URL_REVENUE                = "/api/v1/dsp/file/share/revenue"
	URL_MINER_GET_SHARE_INCOME = "/api/v1/dsp/file/share/income/%d/%d/%d/%d"
)

type RevenueResp struct {
	Revenue       uint64
	RevenueFormat string
}

type Income struct {
	Name         string
	Profit       uint64
	ProfitFormat string
	SharedAt     uint32
}

type MinerGetShardIncomeResp struct {
	TotalIncome       uint64
	TotalIncomeFormat string
	Incomes           []*Income
}

func GenMinerGetShareIncomeUrl(beginTime, endTime uint32, offset, limit uint64) string {
	return fmt.Sprintf(URL_MINER_GET_SHARE_INCOME, beginTime, endTime, offset, limit)
}
