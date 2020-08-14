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
	"encoding/hex"
	"fmt"
	"github.com/ontio/ontology-crypto/keypair"
	"github.com/ontio/ontology/common"
	"github.com/ontio/ontology/core/signature"
	"github.com/ontio/ontology/core/types"
	nvutils "github.com/ontio/ontology/smartcontract/service/native/utils"
	"os"
	"sort"
	"strings"
)

func TransactionFromHexString(rawTx string) (*types.Transaction, error) {
	txData, err := hex.DecodeString(rawTx)
	if err != nil {
		return nil, err
	}
	return types.TransactionFromRawBytes(txData)
}

func AddressFromHexString(s string) (common.Address, error) {
	return common.AddressFromHexString(s)
}

func AddressParseFromBytes(b []byte) (common.Address, error) {
	return common.AddressParseFromBytes(b)
}

func AddressFromBase58(s string) (common.Address, error) {
	return common.AddressFromBase58(s)
}

func Uint256ParseFromBytes(f []byte) (common.Uint256, error) {
	return common.Uint256ParseFromBytes(f)
}

func Uint256FromHexString(s string) (common.Uint256, error) {
	return common.Uint256FromHexString(s)
}

func GetContractAddress(contractCode string) (common.Address, error) {
	code, err := hex.DecodeString(contractCode)
	if err != nil {
		return common.ADDRESS_EMPTY, fmt.Errorf("hex.DecodeString error:%s", err)
	}
	return common.AddressFromVmCode(code), nil
}

func GetAssetAddress(asset string) (common.Address, error) {
	var contractAddress common.Address
	switch strings.ToUpper(asset) {
	case "ONT":
		contractAddress = nvutils.OntContractAddress
	case "ONG":
		contractAddress = nvutils.OngContractAddress
	default:
		return common.ADDRESS_EMPTY, fmt.Errorf("asset:%s not equal ont or ong", asset)
	}
	return contractAddress, nil
}

//IsFileExist return is file is exist
func IsFileExist(file string) bool {
	_, err := os.Stat(file)
	return err == nil || os.IsExist(err)
}

func HasAlreadySig(data []byte, pk keypair.PublicKey, sigDatas [][]byte) bool {
	for _, sigData := range sigDatas {
		err := signature.Verify(pk, data, sigData)
		if err == nil {
			return true
		}
	}
	return false
}

func PubKeysEqual(pks1, pks2 []keypair.PublicKey) bool {
	if len(pks1) != len(pks2) {
		return false
	}
	size := len(pks1)
	if size == 0 {
		return true
	}
	pkstr1 := make([]string, 0, size)
	for _, pk := range pks1 {
		pkstr1 = append(pkstr1, hex.EncodeToString(keypair.SerializePublicKey(pk)))
	}
	pkstr2 := make([]string, 0, size)
	for _, pk := range pks2 {
		pkstr2 = append(pkstr2, hex.EncodeToString(keypair.SerializePublicKey(pk)))
	}
	sort.Strings(pkstr1)
	sort.Strings(pkstr2)
	for i := 0; i < size; i++ {
		if pkstr1[i] != pkstr2[i] {
			return false
		}
	}
	return true
}
