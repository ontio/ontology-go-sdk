package ontology_go_sdk

import (
	"github.com/ontio/ontology/core/types"
	"github.com/ontio/ontology/core/payload"
	sdkcom "github.com/ontio/ontology-go-sdk/common"

	"time"
	"encoding/hex"
	"github.com/ontio/ontology/common"
	"fmt"
	"github.com/ontio/ontology/common/serialization"
	"github.com/ontio/ontology/smartcontract/service/wasmvm"
	"bytes"
	"strconv"
	"encoding/json"
	"encoding/binary"
	"github.com/ontio/ontology/vm/wasmvm/exec"
	"github.com/ontio/ontology/smartcontract/states"
	"github.com/ontio/ontology/core/utils"
)

type WasmVMContract struct{
	ontSdk *OntologySdk
}

func newWasmVMContract(ontSdk *OntologySdk) *WasmVMContract{
	return &WasmVMContract{
		ontSdk: ontSdk,
	}
}

func (this *WasmVMContract) NewDeployWasmVMCodeTransaction(gasPrice, gasLimit uint64, contract *sdkcom.SmartContract) *types.MutableTransaction {
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
func (this *WasmVMContract) DeployWasmVMSmartContract(
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
	tx := this.NewDeployWasmVMCodeTransaction(gasPrice, gasLimit, &sdkcom.SmartContract{
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

//for wasm vm
//build param bytes for wasm contract
func buildWasmContractParam(params []interface{}, paramType wasmvm.ParamType) ([]byte, error) {
	switch paramType {
	case wasmvm.Json:
		args := make([]exec.Param, len(params))

		for i, param := range params {
			switch param.(type) {
			case string:
				arg := exec.Param{Ptype: "string", Pval: param.(string)}
				args[i] = arg
			case int:
				arg := exec.Param{Ptype: "int", Pval: strconv.Itoa(param.(int))}
				args[i] = arg
			case int64:
				arg := exec.Param{Ptype: "int64", Pval: strconv.FormatInt(param.(int64), 10)}
				args[i] = arg
			case []int:
				bf := bytes.NewBuffer(nil)
				array := param.([]int)
				for i, tmp := range array {
					bf.WriteString(strconv.Itoa(tmp))
					if i != len(array)-1 {
						bf.WriteString(",")
					}
				}
				arg := exec.Param{Ptype: "int_array", Pval: bf.String()}
				args[i] = arg
			case []int64:
				bf := bytes.NewBuffer(nil)
				array := param.([]int64)
				for i, tmp := range array {
					bf.WriteString(strconv.FormatInt(tmp, 10))
					if i != len(array)-1 {
						bf.WriteString(",")
					}
				}
				arg := exec.Param{Ptype: "int_array", Pval: bf.String()}
				args[i] = arg
			default:
				return nil, fmt.Errorf("not a supported type :%v\n", param)
			}
		}

		bs, err := json.Marshal(exec.Args{args})
		if err != nil {
			return nil, err
		}
		return bs, nil
	case wasmvm.Raw:
		bf := bytes.NewBuffer(nil)
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

			default:
				return nil, fmt.Errorf("not a supported type :%v\n", param)
			}
		}
		return bf.Bytes(), nil
	default:
		return nil, fmt.Errorf("unsupported type")
	}
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
	paramType wasmvm.ParamType,
	version byte,
	params []interface{}) (common.Uint256, error) {

	contract := &states.ContractInvokeParam{}
	contract.Address = smartcodeAddress
	contract.Method = methodName
	contract.Version = version

	argbytes, err := buildWasmContractParam(params, paramType)

	if err != nil {
		return common.UINT256_EMPTY, fmt.Errorf("build wasm contract param failed:%s", err)
	}
	contract.Args = argbytes
	bf := bytes.NewBuffer(nil)
	contract.Serialize(bf)

	txStruct := utils.TxStruct{}
	txStruct.Address = contract.Address[:]
	txStruct.Version = int(contract.Version)
	txStruct.Method = []byte(contract.Method)
	txStruct.Args = bf.Bytes()

	//bs, err:= json.Marshal(txStruct)
	//if err != nil{
	//	return common.UINT256_EMPTY, fmt.Errorf("build wasm contract param failed:%s", err)
	//
	//}

	bs, err:= txStruct.Serialize()
	if err != nil{
		return common.UINT256_EMPTY, fmt.Errorf("build wasm contract param failed:%s", err)
	}

	tx :=  this.ontSdk.NewInvokeTransaction(gasPrice, gasLimit, bs)
	err = this.ontSdk.SignToTransaction(tx, signer)
	if err != nil {
		return common.Uint256{}, nil
	}
	return this.ontSdk.SendTransaction(tx)
}

func (this *WasmVMContract) PreExecInvokeNeoVMContract(
	contractAddress common.Address,
	methodName string,
	paramType wasmvm.ParamType,
	version byte,
	params []interface{}) (*sdkcom.PreExecResult, error) {


	contract := &states.ContractInvokeParam{}
	contract.Address = contractAddress
	contract.Method = methodName
	contract.Version = version

	argbytes, err := buildWasmContractParam(params, paramType)

	if err != nil {
		return nil, fmt.Errorf("build wasm contract param failed:%s", err)
	}
	contract.Args = argbytes
	bf := bytes.NewBuffer(nil)
	contract.Serialize(bf)

	txStruct := utils.TxStruct{}
	txStruct.Address = contract.Address[:]
	txStruct.Version = int(contract.Version)
	txStruct.Method = []byte(contract.Method)
	txStruct.Args = bf.Bytes()

	//bs, err:= json.Marshal(txStruct)
	//if err != nil{
	//	return nil, fmt.Errorf("build wasm contract param failed:%s", err)
	//
	//}

	bs, err:= txStruct.Serialize()
	if err != nil{
		return nil, fmt.Errorf("build wasm contract param failed:%s", err)
	}


	tx := this.ontSdk.NewInvokeTransaction(0, 0,  bs)
	if err != nil {
		return nil, err
	}
	return this.ontSdk.PreExecTransaction(tx)
}

