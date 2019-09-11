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
