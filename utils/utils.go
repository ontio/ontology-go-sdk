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
//Provide some utils for ontology-go-sdk
package utils

import (
	"bytes"
	"encoding/hex"
	"fmt"
	sdkcom "github.com/ontio/ontology-go-sdk/common"
	"github.com/ontio/ontology/common"
	vmtypes "github.com/ontio/ontology/smartcontract/types"
	neotypes "github.com/ontio/ontology/vm/neovm/types"
	"math/big"
	"os"
)

//ParseUint256FromHexString return Uint256 parse from hex string
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

//ParseAddressFromHexString return address parse from hex string
func ParseAddressFromHexString(address string) (common.Address, error) {
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

//GetContractAddress return contract address
func GetContractAddress(code string, vmType vmtypes.VmType) common.Address {
	data, _ := hex.DecodeString(code)
	vmCode := &vmtypes.VmCode{
		VmType: vmType,
		Code:   data,
	}
	return vmCode.AddressFromVmCode()
}

//GetNeoVMContractAddress return neo vm smart contract address
func GetNeoVMContractAddress(code string) common.Address {
	return GetContractAddress(code, vmtypes.NEOVM)
}

//IsFileExist return is file is exist
func IsFileExist(file string) bool {
	_, err := os.Stat(file)
	return err == nil || os.IsExist(err)
}

//ParseNeoVMSmartContractReturnType return value for result of smart contract execute code.
func ParseNeoVMSmartContractReturnType(value interface{}, returnType sdkcom.NeoVMReturnType) (interface{}, error) {
	switch returnType {
	case sdkcom.NEOVM_TYPE_BOOL:
		return ParseNeoVMSmartContractReturnTypeBool(value)
	case sdkcom.NEOVM_TYPE_INTEGER:
		return ParseNeoVMSmartContractReturnTypeInteger(value)
	case sdkcom.NEOVM_TYPE_STRING:
		return ParseNeoVMSmartContractReturnTypeString(value)
	case sdkcom.NEOVM_TYPE_BYTE_ARRAY:
		return ParseNeoVMSmartContractReturnTypeByteArray(value)
	case sdkcom.NEOVM_TYPE_ARRAY:
		return value, nil
	}
	return value, nil
}

//ParseNeoVMSmartContractReturnTypeBool return bool value of smart contract execute code.
func ParseNeoVMSmartContractReturnTypeBool(val interface{}) (bool, error) {
	hexStr, ok := val.(string)
	if !ok {
		return false, fmt.Errorf("asset to string failed")
	}
	return hexStr == "01", nil
}

//ParseNeoVMSmartContractReturnTypeInteger return integer value of smart contract execute code.
func ParseNeoVMSmartContractReturnTypeInteger(val interface{}) (*big.Int, error) {
	hexStr, ok := val.(string)
	if !ok {
		return nil, fmt.Errorf("asset to string failed")
	}
	data, err := hex.DecodeString(hexStr)
	if err != nil {
		return nil, fmt.Errorf("hex.DecodeString error:%s", err)
	}
	return neotypes.ConvertBytesToBigInteger(data), nil
}

//ParseNeoVMSmartContractReturnTypeByteArray return []byte value of smart contract execute code.
func ParseNeoVMSmartContractReturnTypeByteArray(val interface{}) ([]byte, error) {
	hexStr, ok := val.(string)
	if !ok {
		return nil, fmt.Errorf("asset to string failed")
	}
	data, err := hex.DecodeString(hexStr)
	if err != nil {
		return nil, fmt.Errorf("hex.DecodeString error:%s", err)
	}
	return data, nil
}

//ParseNeoVMSmartContractReturnTypeString return string value of smart contract execute code.
func ParseNeoVMSmartContractReturnTypeString(val interface{}) (string, error) {
	data, err := ParseNeoVMSmartContractReturnTypeByteArray(val)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

//ConvertBigIntegerToBytes return []byte from golang big integer. The big integer of golang is differ with C#, C++ in sign.
func ConvertBigIntegerToBytes(data *big.Int) []byte {
	return neotypes.ConvertBigIntegerToBytes(data)
}

//ConvertBytesToBigInteger return golang big integer  from []byte. The big integer of golang is differ with C#, C++ in sign.
func ConvertBytesToBigInteger(data []byte) *big.Int {
	return neotypes.ConvertBytesToBigInteger(data)
}

//BytesReverse return the reverse of []byte
func BytesReverse(u []byte) []byte {
	for i, j := 0, len(u)-1; i < j; i, j = i+1, j-1 {
		u[i], u[j] = u[j], u[i]
	}
	return u
}
