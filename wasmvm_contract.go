package ontology_go_sdk

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"github.com/ontio/ontology/common"
	"time"

	sdkcom "github.com/ontio/ontology-go-sdk/common"
	"github.com/ontio/ontology/common/serialization"
	"github.com/ontio/ontology/core/payload"
	"github.com/ontio/ontology/core/types"
	"github.com/ontio/ontology/smartcontract/states"
)

type WasmVMContract struct {
	ontSdk *OntologySdk
}

func newWasmVMContract(ontSdk *OntologySdk) *WasmVMContract {
	return &WasmVMContract{
		ontSdk: ontSdk,
	}
}

func (this *WasmVMContract) NewDeployWasmVMCodeTransaction(gasPrice, gasLimit uint64, contract *sdkcom.SmartContract) *types.MutableTransaction {
	deployPayload := &payload.DeployCode{
		Code:        contract.Code,
		VmType:      contract.VmType,
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
	tx := this.NewDeployWasmVMCodeTransaction(gasPrice, gasLimit, &sdkcom.SmartContract{
		Code:        invokeCode,
		VmType:      payload.WASMVM_TYPE,
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

//for wasm vm
//build param bytes for wasm contract
func buildWasmContractParam(method string, params []interface{}) ([]byte, error) {
	bf := bytes.NewBuffer(nil)
	serialization.WriteString(bf, method)
	for _, param := range params {
		switch param.(type) {
		case string:
			tmp := bytes.NewBuffer(nil)
			serialization.WriteString(tmp, param.(string))
			bf.Write(tmp.Bytes())

		case int:
			tmpBytes := make([]byte, 4)
			binary.LittleEndian.PutUint32(tmpBytes, uint32(param.(int)))
			bf.Write(tmpBytes)

		case int64:
			tmpBytes := make([]byte, 8)
			binary.LittleEndian.PutUint64(tmpBytes, uint64(param.(int64)))
			bf.Write(tmpBytes)

		case []byte:
			tmp := bytes.NewBuffer(nil)
			serialization.WriteVarBytes(tmp, param.([]byte))
			bf.Write(tmp.Bytes())
		case common.Uint256:
			bs := param.(common.Uint256)
			parambytes := bs[:]
			bf.Write(parambytes)
		case common.Address:
			bs := param.(common.Address)
			parambytes := bs[:]
			bf.Write(parambytes)
		case byte:
			bf.WriteByte(param.(byte))

		default:
			return nil, fmt.Errorf("not a supported type :%v\n", param)
		}
	}
	return bf.Bytes(), nil

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

	contract := &states.WasmContractParam{}
	contract.Address = smartcodeAddress
	argbytes, err := buildWasmContractParam(methodName, params)

	if err != nil {
		return common.UINT256_EMPTY, fmt.Errorf("build wasm contract param failed:%s", err)
	}
	contract.Args = argbytes
	bf := bytes.NewBuffer(nil)
	contract.Serialize(bf)

	tx := this.ontSdk.NewInvokeWasmTransaction(gasPrice, gasLimit, bf.Bytes())
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

	contract := &states.WasmContractParam{}
	contract.Address = contractAddress

	argbytes, err := buildWasmContractParam(methodName, params)

	if err != nil {
		return nil, fmt.Errorf("build wasm contract param failed:%s", err)
	}
	contract.Args = argbytes
	bf := bytes.NewBuffer(nil)
	contract.Serialize(bf)

	tx := this.ontSdk.NewInvokeWasmTransaction(0, 0, bf.Bytes())
	if err != nil {
		return nil, err
	}
	return this.ontSdk.PreExecTransaction(tx)
}
