package utils

import (
	"encoding/hex"
	"fmt"
	"github.com/ontio/ontology/common"
)

func ParseUint256FromHexString(value string) (common.Uint256, error) {
	data, err := hex.DecodeString(value)
	if err != nil {
		return common.Uint256{}, fmt.Errorf("hex.DecodeString error:%s", err)
	}
	res, err := common.Uint256ParseFromBytes(data)
	if err != nil {
		return common.Uint256{}, fmt.Errorf("Uint160ParseFromBytes error:%s", err)
	}
	return res, nil
}
