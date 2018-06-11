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

//RPC client for ontology
package rpc

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	sdkcom "github.com/ontio/ontology-go-sdk/common"
	"github.com/ontio/ontology-go-sdk/utils"
	"github.com/ontio/ontology/account"
	"github.com/ontio/ontology/common"
	"github.com/ontio/ontology/core/payload"
	"github.com/ontio/ontology/core/types"
	"github.com/ontio/ontology/smartcontract/service/native/ont"
	nvutils "github.com/ontio/ontology/smartcontract/service/native/utils"
	"github.com/ontio/ontology/smartcontract/service/wasmvm"
	cstates "github.com/ontio/ontology/smartcontract/states"
	vmtypes "github.com/ontio/ontology/smartcontract/types"
	"github.com/ontio/ontology/vm/neovm"
	"io/ioutil"
	"math/big"
	"math/rand"
	"net/http"
	"strings"
	"sync/atomic"
	"time"
)

func init() {
	rand.Seed(time.Now().UnixNano())
}

//RpcClient for ontology rpc api
type RpcClient struct {
	qid        uint64
	addr       string
	httpClient *http.Client
}

//NewRpcClient return RpcClient instance
func NewRpcClient() *RpcClient {
	return &RpcClient{
		httpClient: &http.Client{
			Transport: &http.Transport{
				MaxIdleConnsPerHost:   5,
				DisableKeepAlives:     false, //enable keepalive
				IdleConnTimeout:       time.Second * 300,
				ResponseHeaderTimeout: time.Second * 300,
			},
			Timeout: time.Second * 300, //timeout for http response
		},
	}
}

//SetAddress set rpc server address. Simple http://localhost:20336
func (this *RpcClient) SetAddress(addr string) *RpcClient {
	this.addr = addr
	return this
}

//SetHttpClient set http client to RpcClient. In most cases SetHttpClient is not necessary
func (this *RpcClient) SetHttpClient(httpClient *http.Client) *RpcClient {
	this.httpClient = httpClient
	return this
}

//GetVersion return the version of ontology
func (this *RpcClient) GetVersion() (string, error) {
	data, err := this.sendRpcRequest(RPC_GET_VERSION, []interface{}{})
	if err != nil {
		return "", fmt.Errorf("sendRpcRequest error:%s", err)
	}
	version := ""
	err = json.Unmarshal(data, &version)
	if err != nil {
		return "", fmt.Errorf("json.Unmarshal:%s error:%s", data, err)
	}
	return version, nil
}

//GetBlockByHash return block with specified block hash
func (this *RpcClient) GetBlockByHash(hash common.Uint256) (*types.Block, error) {
	return this.GetBlockByHashWithHexString(hex.EncodeToString(hash.ToArray()))
}

//GetBlockByHash return block with specified block hash in hex string code
func (this *RpcClient) GetBlockByHashWithHexString(hash string) (*types.Block, error) {
	data, err := this.sendRpcRequest(RPC_GET_BLOCK, []interface{}{hash})
	if err != nil {
		return nil, fmt.Errorf("sendRpcRequest error:%s", err)
	}
	hexStr := ""
	err = json.Unmarshal(data, &hexStr)
	if err != nil {
		return nil, fmt.Errorf("json.Unmarshal error:%s", err)
	}
	blockData, err := hex.DecodeString(hexStr)
	if err != nil {
		return nil, fmt.Errorf("hex.DecodeString error:%s", err)
	}
	block := &types.Block{}
	buf := bytes.NewBuffer(blockData)
	err = block.Deserialize(buf)
	if err != nil {
		return nil, err
	}
	return block, nil
}

//GetBlockByHeight return block by specified block height
func (this *RpcClient) GetBlockByHeight(height uint32) (*types.Block, error) {
	data, err := this.sendRpcRequest(RPC_GET_BLOCK, []interface{}{height})
	if err != nil {
		return nil, fmt.Errorf("sendRpcRequest error:%s", err)
	}
	hexStr := ""
	err = json.Unmarshal(data, &hexStr)
	if err != nil {
		return nil, fmt.Errorf("json.Unmarshal error:%s", err)
	}
	blockData, err := hex.DecodeString(hexStr)
	if err != nil {
		return nil, fmt.Errorf("hex.DecodeString error:%s", err)
	}
	block := &types.Block{}
	buf := bytes.NewBuffer(blockData)
	err = block.Deserialize(buf)
	if err != nil {
		return nil, err
	}
	return block, nil
}

//GetBlockCount return the total block count of ontology
func (this *RpcClient) GetBlockCount() (uint32, error) {
	data, err := this.sendRpcRequest(RPC_GET_BLOCK_COUNT, []interface{}{})
	if err != nil {
		return 0, fmt.Errorf("sendRpcRequest error:%s", err)
	}
	count := uint32(0)
	err = json.Unmarshal(data, &count)
	if err != nil {
		return 0, fmt.Errorf("json.Unmarshal:%s error:%s", data, err)
	}
	return count, nil
}

//GetCurrentBlockHash return the current block hash of ontology
func (this *RpcClient) GetCurrentBlockHash() (common.Uint256, error) {
	data, err := this.sendRpcRequest(RPC_GET_CURRENT_BLOCK_HASH, []interface{}{})
	if err != nil {
		return common.Uint256{}, fmt.Errorf("sendRpcRequest error:%s", err)
	}
	hexHash := ""
	err = json.Unmarshal(data, &hexHash)
	if err != nil {
		return common.Uint256{}, fmt.Errorf("json.Unmarshal hash:%s error:%s", data, err)
	}
	hash, err := utils.ParseUint256FromHexString(hexHash)
	if err != nil {
		return common.Uint256{}, fmt.Errorf("ParseUint256FromHexString:%s error:%s", data, err)
	}
	return hash, nil
}

//GetBlockHash return block hash by block height
func (this *RpcClient) GetBlockHash(height uint32) (common.Uint256, error) {
	data, err := this.sendRpcRequest(RPC_GET_BLOCK_HASH, []interface{}{height})
	if err != nil {
		return common.Uint256{}, fmt.Errorf("sendRpcRequest error:%s", err)
	}
	hexHash := ""
	err = json.Unmarshal(data, &hexHash)
	if err != nil {
		return common.Uint256{}, fmt.Errorf("json.Unmarshal hash:%s error:%s", data, err)
	}
	hash, err := utils.ParseUint256FromHexString(hexHash)
	if err != nil {
		return common.Uint256{}, fmt.Errorf("ParseUint256FromHexString:%s error:%s", data, err)
	}
	return hash, nil
}

//GetBalance return ont and ong balance of a ontology account
func (this *RpcClient) GetBalance(addr common.Address) (*sdkcom.Balance, error) {
	return this.GetBalanceWithBase58(addr.ToBase58())
}

//GetBalance return ont and ong balance of a ontology account in base58 code address
func (this *RpcClient) GetBalanceWithBase58(base58Addr string) (*sdkcom.Balance, error) {
	data, err := this.sendRpcRequest(RPC_GET_ONT_BALANCE, []interface{}{base58Addr})
	if err != nil {
		return nil, fmt.Errorf("sendRpcRequest error:%s", err)
	}
	balanceRsp := &BalanceRsp{}
	err = json.Unmarshal(data, &balanceRsp)
	if err != nil {
		return nil, fmt.Errorf("json.Unmarshal BalanceRsp:%s error:%s", data, err)
	}
	ont, ok := new(big.Int).SetString(balanceRsp.Ont, 10)
	if !ok {
		return nil, fmt.Errorf("big.Int.SetString ont %s failed", balanceRsp.Ont)
	}
	ong, ok := new(big.Int).SetString(balanceRsp.Ong, 10)
	if !ok {
		return nil, fmt.Errorf("big.Int.SetString ong %s failed", balanceRsp.Ong)
	}
	return &sdkcom.Balance{
		Ont: ont.Uint64(),
		Ong: ong.Uint64(),
	}, nil
}

//GetStorage return smart contract storage item.
//addr is smart contact address
//key is the key of value in smart contract
func (this *RpcClient) GetStorage(smartContractAddress common.Address, key []byte) ([]byte, error) {
	buf := bytes.NewBuffer(nil)
	err := smartContractAddress.Serialize(buf)
	if err != nil {
		return nil, fmt.Errorf("Address Serialize error:%s", err)
	}
	hexString := hex.EncodeToString(buf.Bytes())
	data, err := this.sendRpcRequest(RPC_GET_STORAGE, []interface{}{hexString, hex.EncodeToString(key)})
	if err != nil {
		return nil, fmt.Errorf("sendRpcRequest error:%s", err)
	}
	hexData := ""
	err = json.Unmarshal(data, &hexData)
	if err != nil {
		return nil, fmt.Errorf("json.Unmarshal error:%s", err)
	}
	value, err := hex.DecodeString(hexData)
	if err != nil {
		return nil, fmt.Errorf("hex.DecodeString error:%s", err)
	}
	return value, nil
}

//GetSmartContractEvent return smart contract event execute by invoke transaction.
func (this *RpcClient) GetSmartContractEvent(txHash common.Uint256) (*sdkcom.SmartContactEvent, error) {
	return this.GetSmartContractEventWithHexString(hex.EncodeToString(txHash.ToArray()))
}

//GetSmartContractEvent return smart contract event execute by invoke transaction by hex string code
func (this *RpcClient) GetSmartContractEventWithHexString(txHash string) (*sdkcom.SmartContactEvent, error) {
	data, err := this.sendRpcRequest(RPC_GET_SMART_CONTRACT_EVENT, []interface{}{txHash})
	if err != nil {
		return nil, fmt.Errorf("sendRpcRequest error:%s", err)
	}
	event := &sdkcom.SmartContactEvent{}
	err = json.Unmarshal(data, &event)
	if err != nil {
		return nil, fmt.Errorf("json.Unmarshal SmartContactEvent:%s error:%s", data, err)
	}
	return event, nil
}

//GetRawTransaction return transaction by transaction hash
func (this *RpcClient) GetRawTransaction(txHash common.Uint256) (*types.Transaction, error) {
	return this.GetRawTransactionWithHexString(hex.EncodeToString(txHash.ToArray()))
}

//GetRawTransaction return transaction by transaction hash in hex string code
func (this *RpcClient) GetRawTransactionWithHexString(txHash string) (*types.Transaction, error) {
	data, err := this.sendRpcRequest(RPC_GET_TRANSACTION, []interface{}{txHash})
	if err != nil {
		return nil, fmt.Errorf("sendRpcRequest error:%s", err)
	}
	hexStr := ""
	err = json.Unmarshal(data, &hexStr)
	if err != nil {
		return nil, fmt.Errorf("json.Unmarshal error:%s", err)
	}
	txData, err := hex.DecodeString(hexStr)
	if err != nil {
		return nil, fmt.Errorf("hex.DecodeString error:%s", err)
	}
	buf := bytes.NewBuffer(txData)
	tx := &types.Transaction{}
	err = tx.Deserialize(buf)
	if err != nil {
		return nil, err
	}
	return tx, nil
}

//GetSmartContract return smart contract deployed in ontology by specified smart contract address
func (this *RpcClient) GetSmartContract(smartContractAddress common.Address) (*payload.DeployCode, error) {
	data, err := this.sendRpcRequest(RPC_GET_SMART_CONTRACT, []interface{}{hex.EncodeToString(smartContractAddress[:])})
	if err != nil {
		return nil, fmt.Errorf("sendRpcRequest error:%s", err)
	}
	hexStr := ""
	err = json.Unmarshal(data, &hexStr)
	if err != nil {
		return nil, fmt.Errorf("json.Unmarshal error:%s", err)
	}
	if hexStr == "" {
		return nil, nil
	}
	hexData, err := hex.DecodeString(hexStr)
	if err != nil {
		return nil, fmt.Errorf("hex.DecodeString error:%s", err)
	}
	buf := bytes.NewReader(hexData)
	deploy := &payload.DeployCode{}
	err = deploy.Deserialize(buf)
	if err != nil {
		return nil, err
	}
	return deploy, nil
}

//WaitForGenerateBlock Wait ontology generate block. Default wait 2 blocks.
//return timeout error when there is no block generate in some time.
func (this *RpcClient) WaitForGenerateBlock(timeout time.Duration, blockCount ...uint32) (bool, error) {
	count := uint32(2)
	if len(blockCount) > 0 && blockCount[0] > 0 {
		count = blockCount[0]
	}
	blockHeight, err := this.GetBlockCount()
	if err != nil {
		return false, fmt.Errorf("GetBlockCount error:%s", err)
	}
	secs := int(timeout / time.Second)
	if secs <= 0 {
		secs = 1
	}
	for i := 0; i < secs; i++ {
		time.Sleep(time.Second)
		curBlockHeigh, err := this.GetBlockCount()
		if err != nil {
			continue
		}
		if curBlockHeigh-blockHeight >= count {
			return true, nil
		}
	}
	return false, fmt.Errorf("timeout after %d (s)", secs)
}

//Transfer ONT of ONG
//for ONT amount is the raw value
//for ONG amount is the raw value * 10e9
func (this *RpcClient) Transfer(gasPrice, gasLimit uint64, asset string, from *account.Account, to common.Address, amount uint64) (common.Uint256, error) {
	var contractAddress common.Address
	switch strings.ToUpper(asset) {
	case "ONT":
		contractAddress = nvutils.OntContractAddress
	case "ONG":
		contractAddress = nvutils.OngContractAddress
	default:
		return common.Uint256{}, fmt.Errorf("asset:%s not equal ont or ong", asset)
	}

	buf := bytes.NewBuffer(nil)
	var sts []*ont.State
	sts = append(sts, &ont.State{
		From:  from.Address,
		To:    to,
		Value: amount,
	})
	transfers := &ont.Transfers{
		States: sts,
	}
	err := transfers.Serialize(buf)
	if err != nil {
		return common.Uint256{}, fmt.Errorf("transfers.Serialize error %s", err)
	}
	return this.InvokeNativeContract(gasPrice, gasLimit, from, sdkcom.VERSION_CONTRACT_ONT, contractAddress, sdkcom.NATIVE_TRANSFER, buf.Bytes())
}

func (this *RpcClient) DeploySmartContractTx(
	gasPrice,
	gasLimit uint64,
	vmType vmtypes.VmType,
	needStorage bool,
	code,
	cname,
	cversion,
	cauthor,
	cemail,
	cdesc string,
) (*types.Transaction, error) {
	c, err := hex.DecodeString(code)
	if err != nil {
		return nil, fmt.Errorf("hex.DecodeString error:%s", err)
	}
	return sdkcom.NewDeployCodeTransaction(gasPrice, gasLimit, vmType, c, needStorage, cname, cversion, cauthor, cemail, cdesc), nil
}

//DeploySmartContract Deploy smart contract to ontology
func (this *RpcClient) DeploySmartContract(
	gasPrice,
	gasLimit uint64,
	singer *account.Account,
	vmType vmtypes.VmType,
	needStorage bool,
	code,
	cname,
	cversion,
	cauthor,
	cemail,
	cdesc string) (common.Uint256, error) {
	tx, err := this.DeploySmartContractTx(gasPrice, gasLimit, vmType, needStorage, code, cname, cversion, cauthor, cemail, cdesc)
	if err != nil {
		return common.UINT256_EMPTY, err
	}

	err = sdkcom.SignTransaction(tx, singer)
	if err != nil {
		return common.Uint256{}, err
	}
	txHash, err := this.SendRawTransaction(tx)
	if err != nil {
		return common.Uint256{}, fmt.Errorf("SendRawTransaction error:%s", err)
	}

	return txHash, nil
}

func (this *RpcClient) InvokeNativeContractTx(
	gasPrice,
	gasLimit uint64,
	cversion byte,
	contractAddress common.Address,
	method string,
	args []byte,
) (*types.Transaction, error) {
	return this.InvokeSmartContractTx(gasPrice, gasLimit, vmtypes.Native, cversion, contractAddress, method, args)
}

func (this *RpcClient) InvokeNativeContract(
	gasPrice,
	gasLimit uint64,
	singer *account.Account,
	cversion byte,
	contractAddress common.Address,
	method string,
	args []byte,
) (common.Uint256, error) {
	return this.InvokeSmartContract(gasPrice, gasLimit, singer, vmtypes.Native, cversion, contractAddress, method, args)
}

func (this *RpcClient) InvokeWasmVMSmartContractTx(gasPrice,
	gasLimit uint64,
	cversion byte, //version of contract
	contractAddress common.Address,
	method string,
	paramType wasmvm.ParamType,
	params []interface{}) (*types.Transaction, error) {
	args, err := sdkcom.BuildWasmContractParam(params, paramType)
	if err != nil {
		return nil, fmt.Errorf("build wasm contract param failed:%s", err)
	}
	return this.InvokeSmartContractTx(gasPrice, gasLimit, vmtypes.WASMVM, cversion, contractAddress, method, args)
}

//Invoke wasm smart contract
//methodName is wasm contract action name
//paramType  is Json or Raw format
//version should be greater than 0 (0 is reserved for test)
func (this *RpcClient) InvokeWasmVMSmartContract(
	gasPrice,
	gasLimit uint64,
	siger *account.Account,
	cversion byte, //version of contract
	contractAddress common.Address,
	method string,
	paramType wasmvm.ParamType,
	params []interface{}) (common.Uint256, error) {

	args, err := sdkcom.BuildWasmContractParam(params, paramType)
	if err != nil {
		return common.UINT256_EMPTY, fmt.Errorf("build wasm contract param failed:%s", err)
	}
	return this.InvokeSmartContract(gasPrice, gasLimit, siger, vmtypes.WASMVM, cversion, contractAddress, method, args)
}

func (this *RpcClient) InvokeNeoVMSmartContractTx(
	gasPrice,
	gasLimit uint64,
	cversion byte,
	contractAddress common.Address,
	params []interface{}) (*types.Transaction, error) {
	builder := neovm.NewParamsBuilder(new(bytes.Buffer))
	err := sdkcom.BuildNeoVMParamInter(builder, params)
	if err != nil {
		return nil, err
	}
	args := builder.ToArray()
	return this.InvokeSmartContractTx(gasPrice, gasLimit, vmtypes.NEOVM, cversion, contractAddress, "", args)
}

//Invoke neo vm smart contract. if isPreExec is true, the invoke will not really execute
func (this *RpcClient) InvokeNeoVMSmartContract(
	gasPrice,
	gasLimit uint64,
	siger *account.Account,
	cversion byte,
	contractAddress common.Address,
	params []interface{}) (common.Uint256, error) {

	builder := neovm.NewParamsBuilder(new(bytes.Buffer))
	err := sdkcom.BuildNeoVMParamInter(builder, params)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	args := builder.ToArray()
	return this.InvokeSmartContract(gasPrice, gasLimit, siger, vmtypes.NEOVM, cversion, contractAddress, "", args)
}

//InvokeSmartContract is low level method to invoke contact.
func (this *RpcClient) InvokeSmartContract(
	gasPrice,
	gasLimit uint64,
	singer *account.Account,
	vmType vmtypes.VmType,
	cversion byte,
	contractAddress common.Address,
	method string,
	args []byte,
) (common.Uint256, error) {
	invokeTx, err := this.InvokeSmartContractTx(gasPrice, gasLimit, vmType, cversion, contractAddress, method, args)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	err = sdkcom.SignTransaction(invokeTx, singer)
	if err != nil {
		return common.UINT256_EMPTY, fmt.Errorf("SignTransaction error:%s", err)
	}
	txHash, err := this.SendRawTransaction(invokeTx)
	if err != nil {
		return common.UINT256_EMPTY, fmt.Errorf("SendTransaction error:%s", err)
	}
	return txHash, nil
}

func (this *RpcClient) InvokeSmartContractTx(
	gasPrice,
	gasLimit uint64,
	vmType vmtypes.VmType,
	cversion byte,
	contractAddress common.Address,
	method string,
	args []byte,
) (*types.Transaction, error) {
	crt := &cstates.Contract{
		Version: cversion,
		Address: contractAddress,
		Method:  method,
		Args:    args,
	}
	buf := bytes.NewBuffer(nil)
	err := crt.Serialize(buf)
	if err != nil {
		return nil, fmt.Errorf("Serialize contract error:%s", err)
	}
	invokCode := buf.Bytes()
	if vmType == vmtypes.NEOVM {
		invokCode = append([]byte{0x67}, invokCode[:]...)
	}
	return sdkcom.NewInvokeTransaction(gasPrice, gasLimit, vmType, invokCode), nil
}

func (this *RpcClient) PrepareInvokeSmartContract(tx *types.Transaction) (*cstates.PreExecResult, error) {
	var buffer bytes.Buffer
	err := tx.Serialize(&buffer)
	if err != nil {
		return nil, fmt.Errorf("Serialize error:%s", err)
	}
	txData := hex.EncodeToString(buffer.Bytes())
	data, err := this.sendRpcRequest(RPC_SEND_TRANSACTION, []interface{}{txData, 1})
	if err != nil {
		return nil, fmt.Errorf("sendRpcRequest error:%s", err)
	}
	preResult := &cstates.PreExecResult{}
	err = json.Unmarshal(data, &preResult)
	if err != nil {
		return nil, fmt.Errorf("json.Unmarshal PreExecResult:%s error:%s", data, err)
	}
	return preResult, nil
}

func (this *RpcClient) PrepareInvokeNativeSmartContract(
	cversion byte,
	contractAddress common.Address,
	method string,
	args []byte,
) (*cstates.PreExecResult, error) {
	tx, err := this.InvokeNativeContractTx(0, 0, cversion, contractAddress, method, args)
	if err != nil {
		return nil, err
	}
	return this.PrepareInvokeSmartContract(tx)
}

//PrepareInvokeNeoVMSmartContract return the vm execute result of smart contract but not commit into ledger.
//It's useful for debugging smart contract.
func (this *RpcClient) PrepareInvokeNeoVMSmartContract(
	cversion byte,
	contractAddress common.Address,
	params []interface{},
) (*cstates.PreExecResult, error) {
	tx, err := this.InvokeNeoVMSmartContractTx(0, 0, cversion, contractAddress, params)
	if err != nil {
		return nil, err
	}
	return this.PrepareInvokeSmartContract(tx)
}

func (this *RpcClient) PrepareInvokeNeoVMSmartContractWithRes(
	cversion byte,
	contractAddress common.Address,
	params []interface{},
	returnType sdkcom.NeoVMReturnType,
) (interface{}, error) {
	preResult, err := this.PrepareInvokeNeoVMSmartContract(cversion, contractAddress, params)
	if err != nil {
		return nil, err
	}
	v, err := utils.ParseNeoVMSmartContractReturnType(preResult.Result, returnType)
	if err != nil {
		return nil, fmt.Errorf("ParseNeoVMSmartContractReturnType error:%s", err)
	}
	return v, nil
}

//SendRawTransaction send a transaction to ontology network, and return hash of the transaction
func (this *RpcClient) SendRawTransaction(tx *types.Transaction) (common.Uint256, error) {
	var buffer bytes.Buffer
	err := tx.Serialize(&buffer)
	if err != nil {
		return common.Uint256{}, fmt.Errorf("Serialize error:%s", err)
	}
	txData := hex.EncodeToString(buffer.Bytes())
	data, err := this.sendRpcRequest(RPC_SEND_TRANSACTION, []interface{}{txData})
	if err != nil {
		return common.Uint256{}, err
	}
	hexHash := ""
	err = json.Unmarshal(data, &hexHash)
	if err != nil {
		return common.Uint256{}, fmt.Errorf("json.Unmarshal hash:%s error:%s", data, err)
	}
	hash, err := utils.ParseUint256FromHexString(hexHash)
	if err != nil {
		return common.Uint256{}, fmt.Errorf("ParseUint256FromHexString:%s error:%s", data, err)
	}
	return hash, nil
}

func (this *RpcClient) GetGenerateBlockTime() (int, error) {
	data, err := this.sendRpcRequest(RPC_GET_GENERATE_BLOCK_TIME, []interface{}{})
	if err != nil {
		return 0, fmt.Errorf("sendRpcRequest error:%s", err)
	}
	genTime := 0
	err = json.Unmarshal(data, &genTime)
	if err != nil {
		return 0, fmt.Errorf("json.Unmarshal:%s error:%s", data, err)
	}
	return genTime, nil
}

//GetMerkleProof return the merkle proof whether tx is exist in ledger
func (this *RpcClient) GetMerkleProof(txHash common.Uint256) (*sdkcom.MerkleProof, error) {
	return this.GetMerkleProofWithHexString(hex.EncodeToString(txHash.ToArray()))
}

//GetMerkleProof return the merkle proof whether tx is exist in ledger. Param txHash is in hex string code
func (this *RpcClient) GetMerkleProofWithHexString(txHash string) (*sdkcom.MerkleProof, error) {
	data, err := this.sendRpcRequest(RPC_GET_MERKLE_PROOF, []interface{}{txHash})
	if err != nil {
		return nil, fmt.Errorf("sendRpcRequest error:%s", err)
	}
	proof := &sdkcom.MerkleProof{}
	err = json.Unmarshal(data, proof)
	if err != nil {
		return nil, fmt.Errorf("json.Unmarshal error:%s", err)
	}

	return proof, nil
}

func (this *RpcClient) getQid() string {
	return fmt.Sprintf("%d", atomic.AddUint64(&this.qid, 1))
}

//sendRpcRequest send Rpc request to ontology
func (this *RpcClient) sendRpcRequest(method string, params []interface{}) ([]byte, error) {
	rpcReq := &JsonRpcRequest{
		Version: JSON_RPC_VERSION,
		Id:      this.getQid(),
		Method:  method,
		Params:  params,
	}
	data, err := json.Marshal(rpcReq)
	if err != nil {
		return nil, fmt.Errorf("JsonRpcRequest json.Marsha error:%s", err)
	}
	resp, err := this.httpClient.Post(this.addr, "application/json", strings.NewReader(string(data)))
	if err != nil {
		return nil, fmt.Errorf("http post request:%s error:%s", data, err)
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read rpc response body error:%s", err)
	}
	rpcRsp := &JsonRpcResponse{}
	err = json.Unmarshal(body, rpcRsp)
	if err != nil {
		return nil, fmt.Errorf("json.Unmarshal JsonRpcResponse:%s error:%s", body, err)
	}
	if rpcRsp.Error != 0 {
		return nil, fmt.Errorf("sendRpcRequest error code:%d desc:%s result:%s", rpcRsp.Error, rpcRsp.Desc, rpcRsp.Result)
	}
	return rpcRsp.Result, nil
}

//SendEmergencyGovReq return error
func (this *RpcClient) SendEmergencyGovReq(block []byte) (error) {
	blockString := hex.EncodeToString(block)
	_, err := this.sendRpcRequest(SEND_EMERGENCY_GOV_REQ, []interface{}{blockString})
	if err != nil {
		return  fmt.Errorf("sendRpcRequest error:%s", err)
	}
	return nil
}
//GetGetBlockRoot return common.Uint256
func (this *RpcClient) GetBlockRootWithNewTxRoot(txRoot common.Uint256) (common.Uint256,error) {

	hashString := hex.EncodeToString(txRoot.ToArray())
	data, err := this.sendRpcRequest(GET_BLOCK_ROOT_WITH_NEW_TX_ROOT, []interface{}{hashString})
	if err != nil {
		return common.Uint256{}, err
	}
	hexHash := ""
	err = json.Unmarshal(data, &hexHash)
	if err != nil {
		return common.Uint256{}, fmt.Errorf("json.Unmarshal hash:%s error:%s", data, err)
	}
	hash, err := utils.ParseUint256FromHexString(hexHash)
	if err != nil {
		return common.Uint256{}, fmt.Errorf("ParseUint256FromHexString:%s error:%s", data, err)
	}
	return hash, nil
}