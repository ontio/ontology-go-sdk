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
	httpcom "github.com/ontio/ontology/http/base/common"
	"github.com/ontio/ontology/smartcontract/service/native/ont"
	nutils "github.com/ontio/ontology/smartcontract/service/native/utils"
	cstates "github.com/ontio/ontology/smartcontract/states"
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
	return this.GetBlockByHashWithHexString(hash.ToHexString())
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
	hash, err := common.Uint256FromHexString(hexHash)
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
	hash, err := common.Uint256FromHexString(hexHash)
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
func (this *RpcClient) GetStorage(contractAddress common.Address, key []byte) ([]byte, error) {
	data, err := this.sendRpcRequest(RPC_GET_STORAGE, []interface{}{contractAddress.ToHexString(), hex.EncodeToString(key)})
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
	return this.GetSmartContractEventWithHexString(txHash.ToHexString())
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

func (this *RpcClient) GetSmartContractEventByBlock(blockHeight uint32) ([]*sdkcom.SmartContactEvent, error) {
	data, err := this.sendRpcRequest(RPC_GET_SMART_CONTRACT_EVENT, []interface{}{blockHeight})
	if err != nil {
		return nil, fmt.Errorf("sendRpcRequest error:%s", err)
	}
	events := make([]*sdkcom.SmartContactEvent, 0)
	err = json.Unmarshal(data, &events)
	if err != nil {
		return nil, fmt.Errorf("json.Unmarshal SmartContactEvent:%s error:%s", data, err)
	}
	return events, nil
}

//GetRawTransaction return transaction by transaction hash
func (this *RpcClient) GetRawTransaction(txHash common.Uint256) (*types.Transaction, error) {
	return this.GetRawTransactionWithHexString(txHash.ToHexString())
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
	data, err := this.sendRpcRequest(RPC_GET_SMART_CONTRACT, []interface{}{smartContractAddress.ToHexString()})
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
	return this.GetMerkleProofWithHexString(txHash.ToHexString())
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
	tx, err := this.NewTransferTransaction(gasPrice, gasLimit, asset, from.Address, to, amount)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	err = this.SignToTransaction(tx, from)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	return this.SendRawTransaction(tx)
}

func (this *RpcClient) Allowance(asset string, from, to common.Address) (uint64, error) {
	type allowanceStruct struct {
		From common.Address
		To   common.Address
	}
	contractAddress, err := utils.GetAssetAddress(asset)
	if err != nil {
		return 0, err
	}
	result, err := this.PrepareInvokeNativeContract(contractAddress, sdkcom.VERSION_CONTRACT_ONT, sdkcom.NATIVE_ALLOWANCE, []interface{}{
		&allowanceStruct{
			From: from,
			To:   to,
		}})
	if err != nil {
		return 0, fmt.Errorf("PrepareInvokeNativeContract error:%s", err)
	}
	if result.State == 0 {
		return 0, fmt.Errorf("prepare inoke failed")
	}
	data, err := hex.DecodeString(result.Result.(string))
	if err != nil {
		return 0, fmt.Errorf("hex.DecodeString error:%s", err)
	}
	return new(big.Int).SetBytes(data).Uint64(), nil
}

func (this *RpcClient) Approve(gasPrice, gasLimit uint64, asset string, from *account.Account, to common.Address, amount uint64) (common.Uint256, error) {
	tx, err := this.NewApproveTransaction(gasPrice, gasLimit, asset, from.Address, to, amount)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	err = this.SignToTransaction(tx, from)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	return this.SendRawTransaction(tx)
}

func (this *RpcClient) TransferFrom(gasPrice, gasLimit uint64, asset string, sender *account.Account, from, to common.Address, amount uint64) (common.Uint256, error) {
	tx, err := this.NewTransferFromTransaction(gasPrice, gasLimit, asset, sender.Address, from, to, amount)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	err = this.SignToTransaction(tx, sender)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	return this.SendRawTransaction(tx)
}

func (this *RpcClient) UnboundONG(user common.Address) (uint64, error) {
	return this.Allowance("ong", nutils.OngContractAddress, user)
}

func (this *RpcClient) WithdrawONG(gasPrice, gasLimit uint64, user *account.Account, withdrawAmount ...uint64) (common.Uint256, error) {
	var amount uint64
	var err error
	if len(withdrawAmount) > 0 {
		amount = withdrawAmount[0]
	}
	if amount == 0 {
		amount, err = this.UnboundONG(user.Address)
		if err != nil {
			return common.UINT256_EMPTY, fmt.Errorf("Get UnboundONG error:%s", err)
		}
	}
	if amount == 0 {
		return common.UINT256_EMPTY, nil
	}
	return this.TransferFrom(gasPrice, gasLimit, "ong", user, nutils.OngContractAddress, user.Address, amount)
}

func (this *RpcClient) NewTransferTransaction(gasPrice, gasLimit uint64, asset string, from, to common.Address, amount uint64) (*types.Transaction, error) {
	contractAddress, err := utils.GetAssetAddress(asset)
	if err != nil {
		return nil, err
	}
	var sts []*ont.State
	sts = append(sts, &ont.State{
		From:  from,
		To:    to,
		Value: amount,
	})
	return this.NewNativeInvokeTransaction(gasPrice, gasLimit, sdkcom.VERSION_CONTRACT_ONT, contractAddress, sdkcom.NATIVE_TRANSFER, []interface{}{sts})
}

func (this *RpcClient) NewApproveTransaction(gasPrice, gasLimit uint64, asset string, from, to common.Address, amount uint64) (*types.Transaction, error) {
	contractAddress, err := utils.GetAssetAddress(asset)
	if err != nil {
		return nil, err
	}
	st := &ont.State{
		From:  from,
		To:    to,
		Value: amount,
	}
	return this.NewNativeInvokeTransaction(gasPrice, gasLimit, sdkcom.VERSION_CONTRACT_ONT, contractAddress, sdkcom.NATIVE_APPROVE, []interface{}{st})
}

func (this *RpcClient) NewTransferFromTransaction(gasPrice, gasLimit uint64, asset string, sender, from, to common.Address, amount uint64) (*types.Transaction, error) {
	contractAddress, err := utils.GetAssetAddress(asset)
	if err != nil {
		return nil, err
	}
	st := &ont.TransferFrom{
		Sender: sender,
		From:   from,
		To:     to,
		Value:  amount,
	}
	return this.NewNativeInvokeTransaction(gasPrice, gasLimit, sdkcom.VERSION_CONTRACT_ONT, contractAddress, sdkcom.NATIVE_TRANSFER_FROM, []interface{}{st})
}

//DeploySmartContract Deploy smart contract to ontology
func (this *RpcClient) DeploySmartContract(
	gasPrice,
	gasLimit uint64,
	singer *account.Account,
	needStorage bool,
	code,
	cname,
	cversion,
	cauthor,
	cemail,
	cdesc string) (common.Uint256, error) {

	invokeCode, err := hex.DecodeString(code)
	if err != nil {
		return common.UINT256_EMPTY, fmt.Errorf("code hex decode error:%s", err)
	}
	tx := this.NewDeployCodeTransaction(gasPrice, gasLimit, invokeCode, needStorage, cname, cversion, cauthor, cemail, cdesc)
	err = this.SignToTransaction(tx, singer)
	if err != nil {
		return common.Uint256{}, err
	}
	txHash, err := this.SendRawTransaction(tx)
	if err != nil {
		return common.Uint256{}, fmt.Errorf("SendRawTransaction error:%s", err)
	}
	return txHash, nil
}

func (this *RpcClient) InvokeNativeContract(
	gasPrice,
	gasLimit uint64,
	singer *account.Account,
	cversion byte,
	contractAddress common.Address,
	method string,
	params []interface{},
) (common.Uint256, error) {
	tx, err := this.NewNativeInvokeTransaction(gasPrice, gasLimit, cversion, contractAddress, method, params)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	err = this.SignToTransaction(tx, singer)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	return this.SendRawTransaction(tx)
}

//Invoke neo vm smart contract.
func (this *RpcClient) InvokeNeoVMContract(
	gasPrice,
	gasLimit uint64,
	signer *account.Account,
	contractAddress common.Address,
	params []interface{}) (common.Uint256, error) {

	tx, err := this.NewNeoVMSInvokeTransaction(gasPrice, gasLimit, contractAddress, params)
	if err != nil {
		return common.UINT256_EMPTY, fmt.Errorf("NewNeoVMSInvokeTransaction error:%s", err)
	}
	err = this.SignToTransaction(tx, signer)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	return this.SendRawTransaction(tx)
}

func (this *RpcClient) NewDeployCodeTransaction(
	gasPrice, gasLimit uint64,
	code []byte,
	needStorage bool,
	cname, cversion, cauthor, cemail, cdesc string) *types.Transaction {
	return sdkcom.NewDeployCodeTransaction(gasPrice, gasLimit, code, needStorage, cname, cversion, cauthor, cemail, cdesc)
}

func (this *RpcClient) NewNativeInvokeTransaction(gasPrice,
	gasLimit uint64,
	cversion byte,
	contractAddress common.Address,
	method string,
	params []interface{},
) (*types.Transaction, error) {
	if params == nil {
		params = make([]interface{}, 0, 1)
	}
	//Params cannot empty, if params is empty, fulfil with empty string
	if len(params) == 0 {
		params = append(params, "")
	}
	invokeCode, err := httpcom.BuildNativeInvokeCode(contractAddress, cversion, method, params)
	if err != nil {
		return nil, fmt.Errorf("BuildNativeInvokeCode error:%s", err)
	}
	return sdkcom.NewInvokeTransaction(gasPrice, gasLimit, invokeCode), nil
}

func (this *RpcClient) NewNeoVMSInvokeTransaction(
	gasPrice, gasLimit uint64,
	contractAddress common.Address,
	params []interface{},
) (*types.Transaction, error) {

	invokeCode, err := httpcom.BuildNeoVMInvokeCode(contractAddress, params)
	if err != nil {
		return nil, err
	}
	return sdkcom.NewInvokeTransaction(gasPrice, gasLimit, invokeCode), nil
}

//PrepareInvokeNeoVMContractWithRes Prepare invoke neovm contract, and return the value of result.
//Param returnType must be one of NeoVMReturnType, or array of NeoVMReturnType
func (this *RpcClient) PrepareInvokeNeoVMContractWithRes(contractAddress common.Address, params []interface{}, returnType interface{}) (interface{}, error) {
	preResult, err := this.PrepareInvokeNeoVMContract(contractAddress, params)
	if err != nil {
		return nil, err
	}
	v, err := utils.ParsePreExecResult(preResult.Result, returnType)
	if err != nil {
		return nil, fmt.Errorf("ParseNeoVMContractReturnType error:%s", err)
	}
	return v, nil
}

func (this *RpcClient) PrepareInvokeNeoVMContract(contractAddress common.Address,
	params []interface{}) (*cstates.PreExecResult, error) {
	this.NewNeoVMSInvokeTransaction(0, 0, contractAddress, params)

	tx, err := this.NewNeoVMSInvokeTransaction(0, 0, contractAddress, params)
	if err != nil {
		return nil, fmt.Errorf("NewNeoVMSInvokeTransaction error:%s", err)
	}
	return this.PrepareInvokeContract(tx)
}

func (this *RpcClient) PrepareInvokeNativeContract(contractAddress common.Address, version byte, method string, params []interface{}) (*cstates.PreExecResult, error) {
	tx, err := this.NewNativeInvokeTransaction(0, 0, version, contractAddress, method, params)
	if err != nil {
		return nil, fmt.Errorf("NewNeoVMSInvokeTransaction error:%s", err)
	}
	return this.PrepareInvokeContract(tx)
}

//PrepareInvokeNativeContractWithRes Prepare invoke native contract, and return the value of result.
//Param returnType must be one of NeoVMReturnType, or array of NeoVMReturnType
func (this *RpcClient) PrepareInvokeNativeContractWithRes(contractAddress common.Address, version byte, method string, params, returnType []interface{}) (interface{}, error) {
	preResult, err := this.PrepareInvokeNativeContract(contractAddress, version, method, params)
	if err != nil {
		return nil, err
	}
	v, err := utils.ParsePreExecResult(preResult.Result, returnType)
	if err != nil {
		return nil, fmt.Errorf("ParseNeoVMContractReturnType error:%s", err)
	}
	return v, nil
}

//PrepareInvokeContract return the vm execute result of smart contract but not commit into ledger.
//It's useful for debugging smart contract.
func (this *RpcClient) PrepareInvokeContract(tx *types.Transaction) (*cstates.PreExecResult, error) {
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

func (this *RpcClient) SignToTransaction(tx *types.Transaction, signer *account.Account) error {
	return sdkcom.SignToTransaction(tx, signer)
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
	hash, err := common.Uint256FromHexString(hexHash)
	if err != nil {
		return common.Uint256{}, fmt.Errorf("ParseUint256FromHexString:%s error:%s", data, err)
	}
	return hash, nil
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
func (this *RpcClient) SendEmergencyGovReq(block []byte) error {
	blockString := hex.EncodeToString(block)
	_, err := this.sendRpcRequest(SEND_EMERGENCY_GOV_REQ, []interface{}{blockString})
	if err != nil {
		return fmt.Errorf("sendRpcRequest error:%s", err)
	}
	return nil
}

//GetGetBlockRoot return common.Uint256
func (this *RpcClient) GetBlockRootWithNewTxRoot(txRoot common.Uint256) (common.Uint256, error) {

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

	hash, err := common.Uint256FromHexString(hexHash)
	if err != nil {
		return common.Uint256{}, fmt.Errorf("ParseUint256FromHexString:%s error:%s", data, err)
	}
	return hash, nil
}
