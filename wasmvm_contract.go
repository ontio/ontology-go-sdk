package ontology_go_sdk

import (
	"encoding/hex"
	"fmt"
	sdkcom "github.com/ontio/ontology-go-sdk/common"
	utils2 "github.com/ontio/ontology/cmd/utils"
	"github.com/ontio/ontology/common"
	"github.com/ontio/ontology/core/payload"
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

//Invoke wasm smart contract
//methodName is wasm contract action name
//paramType  is Json or Raw format
//version should be greater than 0 (0 is reserved for test)
func (this *WasmVMContract) InvokeWasmVMSmartContract(
	gasPrice,
	gasLimit uint64,
	signer *Account,
	smartcodeAddress common.Address,
	methodName string,
	params []interface{}) (common.Uint256, error) {
	args := make([]interface{}, 1+len(params))
	args[0] = methodName
	copy(args[1:], params[:])
	tx, err := utils.NewWasmVMInvokeTransaction(gasPrice, gasLimit, smartcodeAddress, args)
	if err != nil {
		return common.UINT256_EMPTY, err
	}

	err = this.ontSdk.SignToTransaction(tx, signer)
	if err != nil {
		return common.Uint256{}, nil
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
