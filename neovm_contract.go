package ontology_go_sdk

import (
	"encoding/hex"
	"fmt"
	sdkcom "github.com/ontio/ontology-go-sdk/common"
	"github.com/ontio/ontology/common"
	"github.com/ontio/ontology/core/payload"
	"github.com/ontio/ontology/core/types"
	"time"
)

type NeoVMContract struct {
	ontSdk *OntologySdk
}

func newNeoVMContract(ontSdk *OntologySdk) *NeoVMContract {
	return &NeoVMContract{
		ontSdk: ontSdk,
	}
}

func (this *NeoVMContract) NewDeployNeoVMCodeTransaction(gasPrice, gasLimit uint64, contract *sdkcom.SmartContract) *types.MutableTransaction {
	deployPayload := &payload.DeployCode{
		Code:        contract.Code,
		NeedStorage: contract.NeedStorage,
		Name:        contract.Name,
		Version:     contract.Version,
		Author:      contract.Author,
		Email:       contract.Email,
		Description: contract.Description,
	}
	tx := &types.MutableTransaction{
		Version:  sdkcom.VERSION_TRANSACTION,
		TxType:   types.Deploy,
		Nonce:    uint32(time.Now().Unix()),
		Payload:  deployPayload,
		GasPrice: gasPrice,
		GasLimit: gasLimit,
		Sigs:     make([]types.Sig, 0, 0),
	}
	return tx
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
	tx := this.NewDeployNeoVMCodeTransaction(gasPrice, gasLimit, &sdkcom.SmartContract{
		Code:        invokeCode,
		NeedStorage: needStorage,
		Name:        name,
		Version:     version,
		Author:      author,
		Email:       email,
		Description: desc,
	})
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
