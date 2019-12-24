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
package ontology_go_sdk

import (
	"encoding/hex"
	"fmt"
	sdkcom "github.com/ontio/ontology-go-sdk/common"
	utils2 "github.com/ontio/ontology/cmd/utils"
	"github.com/ontio/ontology/common"
	"github.com/ontio/ontology/core/payload"
	"github.com/ontio/ontology/core/types"
	"github.com/ontio/ontology/core/utils"
)

type WasmVMContract struct {
	ontSdk *OntologySdk
}

func newWasmVMContract(ontSdk *OntologySdk) *WasmVMContract {
	return &WasmVMContract{
		ontSdk: ontSdk,
	}
}

//DeploySmartContract Deploy smart contract to ontology
func (this *WasmVMContract) DeployWasmVMSmartContract(
	gasPrice,
	gasLimit uint64,
	singer *Account,
	code,
	name,
	version,
	author,
	email,
	desc string) (common.Uint256, error) {

	invokeCode, err := hex.DecodeString(code)
	if err != nil {
		return common.UINT256_EMPTY, fmt.Errorf("code hex decode error:%s", err)
	}
	tx, err := utils2.NewDeployCodeTransaction(gasPrice, gasLimit, invokeCode, payload.WASMVM_TYPE, name, version, author, email, desc)
	err = this.ontSdk.SignToTransaction(tx, singer)
	if err != nil {
		return common.Uint256{}, err
	}
	txHash, err := this.ontSdk.SendTransaction(tx)
	if err != nil {
		return common.Uint256{}, fmt.Errorf("SendRawTransaction error:%s", err)
	}
	return txHash, nil
}

func (this *WasmVMContract) NewInvokeWasmVmTransaction(gasPrice,
	gasLimit uint64,
	smartcodeAddress common.Address,
	methodName string,
	params []interface{}) (*types.MutableTransaction, error) {
	args := make([]interface{}, 1+len(params))
	args[0] = methodName
	copy(args[1:], params[:])
	tx, err := utils.NewWasmVMInvokeTransaction(gasPrice, gasLimit, smartcodeAddress, args)
	if err != nil {
		return nil, err
	}
	return tx, nil
}

//Invoke wasm smart contract
//methodName is wasm contract action name
//paramType  is Json or Raw format
//version should be greater than 0 (0 is reserved for test)
func (this *WasmVMContract) InvokeWasmVMSmartContract(
	gasPrice,
	gasLimit uint64,
	payer,
	signer *Account,
	smartcodeAddress common.Address,
	methodName string,
	params []interface{}) (common.Uint256, error) {
	tx, err := this.NewInvokeWasmVmTransaction(gasPrice, gasLimit, smartcodeAddress, methodName, params)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	if payer != nil {
		this.ontSdk.SetPayer(tx, payer.Address)
		err = this.ontSdk.SignToTransaction(tx, signer)
		if err != nil {
			return common.Uint256{}, fmt.Errorf("payer sign tx error: %s", err)
		}
	}
	err = this.ontSdk.SignToTransaction(tx, signer)
	if err != nil {
		return common.Uint256{}, err
	}
	return this.ontSdk.SendTransaction(tx)
}

func (this *WasmVMContract) PreExecInvokeWasmVMContract(
	contractAddress common.Address,
	methodName string,
	params []interface{}) (*sdkcom.PreExecResult, error) {
	args := make([]interface{}, 1+len(params))
	args[0] = methodName
	copy(args[1:], params[:])
	tx, err := utils.NewWasmVMInvokeTransaction(0, 0, contractAddress, args)
	if err != nil {
		return nil, err
	}
	return this.ontSdk.PreExecTransaction(tx)
}
