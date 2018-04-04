package utils

import (
	"encoding/hex"
	"fmt"
	"github.com/ontio/ontology/common"
	"os"
	vmtypes"github.com/ontio/ontology/vm/types"
	"bytes"
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

func ParseAddressFromHexString(address string)(common.Address,error){
	data, err := hex.DecodeString(address)
	if err != nil {
		return common.Address{}, fmt.Errorf("hex.DecodeString error:%s", err)
	}
	var addr common.Address
	err = addr.Deserialize(bytes.NewBuffer(data))
	if err != nil {
		return common.Address{}, fmt.Errorf("Address Deserialize error:%s", err)
	}
	return addr, nil
}

func IsFileExist(file string) bool {
	_, err := os.Stat(file)
	return err == nil || os.IsExist(err)
}

func GetContractAddress(code string, vmType vmtypes.VmType) common.Address {
	data, _ := hex.DecodeString(code)
	vmCode := &vmtypes.VmCode{
		VmType: vmType,
		Code:   data,
	}
	return vmCode.AddressFromVmCode()
}

func GetNeoVMContractAddress(code string)common.Address{
	return GetContractAddress(code, vmtypes.NEOVM)
}