package ontology_go_sdk

import (
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

func (this *NeoVMContract) NewDeployNeoVMCodeTransaction(gasPrice, gasLimit uint64, contract payload.DeployCode) (*types.MutableTransaction, error) {

	return utils.NewDeployCodeTransaction(gasPrice, gasLimit, contract.GetRawCode(), payload.NEOVM_TYPE, contract.Name,
		contract.Version, contract.Author, contract.Email, contract.Description)
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
	codeBs, err := common.HexToBytes(code)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	tx, err := utils.NewDeployCodeTransaction(gasPrice, gasLimit, codeBs, payload.NEOVM_TYPE, name, version, author, email, desc)
	err = this.ontSdk.SignToTransaction(tx, singer)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	return this.ontSdk.SendTransaction(tx)
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
	payer,
	signer *Account,
	contractAddress common.Address,
	params []interface{}) (common.Uint256, error) {
	tx, err := this.NewNeoVMInvokeTransaction(gasPrice, gasLimit, contractAddress, params)
	if err != nil {
		return common.UINT256_EMPTY, fmt.Errorf("NewNeoVMInvokeTransaction error:%s", err)
	}
	if payer != nil {
		this.ontSdk.SetPayer(tx, payer.Address)
		err = this.ontSdk.SignToTransaction(tx, payer)
		if err != nil {
			return common.UINT256_EMPTY, err
		}
	}
	err = this.ontSdk.SignToTransaction(tx, signer)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	hash := tx.Hash()
	fmt.Println("txhash:", hash.ToHexString())
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
