package ontology_go_sdk

import (
	"encoding/hex"
	"fmt"
	sdkcom "github.com/ontio/ontology-go-sdk/common"
	"github.com/ontio/ontology/cmd/utils"
	"github.com/ontio/ontology/common"
	"github.com/ontio/ontology/core/payload"
	"github.com/ontio/ontology/core/types"
	httpcom "github.com/ontio/ontology/http/base/common"
)

type NeoVMContract struct {
	ontSdk *OntologySdk
}

func newNeoVMContract(ontSdk *OntologySdk) *NeoVMContract {
	return &NeoVMContract{
		ontSdk: ontSdk,
	}
}

//DeploySmartContract Deploy smart contract to ontology
func (this *NeoVMContract) DeployNeoVMSmartContract(
	gasPrice,
	gasLimit uint64,
	singer *Account,
	needStorage bool,
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
	tx, err := utils.NewDeployCodeTransaction(gasPrice, gasLimit, invokeCode, payload.NEOVM_TYPE, name, version, author, email, desc)
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

func (this *NeoVMContract) NewNeoVMInvokeTransaction(
	gasPrice,
	gasLimit uint64,
	contractAddress common.Address,
	params []interface{},
) (*types.MutableTransaction, error) {
	invokeCode, err := httpcom.BuildNeoVMInvokeCode(contractAddress, params)
	if err != nil {
		return nil, err
	}
	return this.ontSdk.NewInvokeTransaction(gasPrice, gasLimit, invokeCode), nil
}

func (this *NeoVMContract) InvokeNeoVMContract(
	gasPrice,
	gasLimit uint64,
	signer *Account,
	contractAddress common.Address,
	params []interface{}) (common.Uint256, error) {
	tx, err := this.NewNeoVMInvokeTransaction(gasPrice, gasLimit, contractAddress, params)
	if err != nil {
		return common.UINT256_EMPTY, fmt.Errorf("NewNeoVMInvokeTransaction error:%s", err)
	}
	err = this.ontSdk.SignToTransaction(tx, signer)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	return this.ontSdk.SendTransaction(tx)
}

func (this *NeoVMContract) PreExecInvokeNeoVMContract(
	contractAddress common.Address,
	params []interface{}) (*sdkcom.PreExecResult, error) {
	tx, err := this.NewNeoVMInvokeTransaction(0, 0, contractAddress, params)
	if err != nil {
		return nil, err
	}
	return this.ontSdk.PreExecTransaction(tx)
}
