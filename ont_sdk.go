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

//Ontolog sdk in golang. Using for operation with ontology
package ontology_go_sdk

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/ontio/ontology-crypto/keypair"
	sdkcom "github.com/ontio/ontology-go-sdk/common"
	"github.com/ontio/ontology-go-sdk/rest"
	"github.com/ontio/ontology-go-sdk/rpc"
	"github.com/ontio/ontology-go-sdk/utils"
	"github.com/ontio/ontology-go-sdk/ws"
	"github.com/ontio/ontology/account"
	"github.com/ontio/ontology/common"
	"github.com/ontio/ontology/core/types"
	"sync/atomic"
)

//OntologySdk is the main struct for user
type OntologySdk struct {
	Rpc       *rpc.RpcClient   //Rpc client used the rpc api of ontology
	Rest      *rest.RestClient //Rest client used the rest api of ontology
	Ws        *ws.WSClient     //Web socket client used the web socket api of ontology
	defClient sdkcom.OntologyClient
	Native    *NativeContract
	qid       uint64
}

//NewOntologySdk return OntologySdk.
func NewOntologySdk() *OntologySdk {
	ontSdk := &OntologySdk{}
	native := newNativeContract(ontSdk)
	ontSdk.Native = native
	return ontSdk
}

//OpenOrCreateWallet return a wllet instance.If the wallet is exist, just open it. if not, then create and open.
func (this *OntologySdk) OpenOrCreateWallet(walletFile string) (account.Client, error) {
	if utils.IsFileExist(walletFile) {
		return this.OpenWallet(walletFile)
	} else {
		return this.CreateWallet(walletFile)
	}
}

//CreateWallet return a new wallet
func (this *OntologySdk) CreateWallet(walletFile string) (account.Client, error) {
	if utils.IsFileExist(walletFile) {
		return nil, fmt.Errorf("wallet:%s has already exist", walletFile)
	}
	return account.Open(walletFile)
}

//OpenWallet return a wallet instance
func (this *OntologySdk) OpenWallet(walletFile string) (account.Client, error) {
	return account.Open(walletFile)
}

func (this *OntologySdk) NewRpcClient() *rpc.RpcClient {
	this.Rpc = rpc.NewRpcClient()
	return this.Rpc
}

func (this *OntologySdk) NewRestClient() *rest.RestClient {
	this.Rest = rest.NewRestClient()
	return this.Rest
}

func (this *OntologySdk) NewWebSocketClient() *ws.WSClient {
	wsClient := ws.NewWSClient()
	this.Ws = wsClient
	return wsClient
}

func (this *OntologySdk) SetDefaultClient(client sdkcom.OntologyClient) {
	this.defClient = client
}

func (this *OntologySdk) GetCurrentBlockHeight() (uint32, error) {
	client := this.getClient()
	if client == nil {
		return 0, fmt.Errorf("don't have available client of ontology")
	}
	data, err := client.GetCurrentBlockHeight(this.getNextQid())
	if err != nil {
		return 0, err
	}
	return utils.GetUint32(data)
}

func (this *OntologySdk) GetCurrentBlockHash() (common.Uint256, error) {
	client := this.getClient()
	if client == nil {
		return common.UINT256_EMPTY, fmt.Errorf("don't have available client of ontology")
	}
	data, err := client.GetCurrentBlockHash(this.getNextQid())
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	return utils.GetUint256(data)
}

func (this *OntologySdk) GetBlockByHeight(height uint32) (*types.Block, error) {
	client := this.getClient()
	if client == nil {
		return nil, fmt.Errorf("don't have available client of ontology")
	}
	data, err := client.GetBlockByHeight(this.getNextQid(), height)
	if err != nil {
		return nil, err
	}
	return utils.GetBlock(data)
}

func (this *OntologySdk) GetBlockByHash(blockHash string) (*types.Block, error) {
	client := this.getClient()
	if client == nil {
		return nil, fmt.Errorf("don't have available client of ontology")
	}
	data, err := client.GetBlockByHash(this.getNextQid(), blockHash)
	if err != nil {
		return nil, err
	}
	return utils.GetBlock(data)
}

func (this *OntologySdk) GetTransaction(txHash string) (*types.Transaction, error) {
	client := this.getClient()
	if client == nil {
		return nil, fmt.Errorf("don't have available client of ontology")
	}
	data, err := client.GetRawTransaction(this.getNextQid(), txHash)
	if err != nil {
		return nil, err
	}
	return utils.GetTransaction(data)
}

func (this *OntologySdk) GetBlockHash(height uint32) (common.Uint256, error) {
	client := this.getClient()
	if client == nil {
		return common.UINT256_EMPTY, fmt.Errorf("don't have available client of ontology")
	}
	data, err := client.GetBlockHash(this.getNextQid(), height)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	return utils.GetUint256(data)
}

func (this *OntologySdk) GetBlockHeightByTxHash(txHash string) (uint32, error) {
	client := this.getClient()
	if client == nil {
		return 0, fmt.Errorf("don't have available client of ontology")
	}
	data, err := client.GetBlockHeightByTxHash(this.getNextQid(), txHash)
	if err != nil {
		return 0, err
	}
	return utils.GetUint32(data)
}

func (this *OntologySdk) GetBlockTxHashesByHeight(height uint32) (*sdkcom.BlockTxHashes, error) {
	client := this.getClient()
	if client == nil {
		return nil, fmt.Errorf("don't have available client of ontology")
	}
	data, err := client.GetBlockTxHashesByHeight(this.getNextQid(), height)
	if err != nil {
		return nil, err
	}
	return utils.GetBlockTxHashes(data)
}

func (this *OntologySdk) GetStorage(contractAddress string, key []byte) ([]byte, error) {
	client := this.getClient()
	if client == nil {
		return nil, fmt.Errorf("don't have available client of ontology")
	}
	data, err := client.GetStorage(this.getNextQid(), contractAddress, key)
	if err != nil {
		return nil, err
	}
	return utils.GetStorage(data)
}

func (this *OntologySdk) GetSmartContract(contractAddress string) (*sdkcom.SmartContract, error) {
	client := this.getClient()
	if client == nil {
		return nil, fmt.Errorf("don't have available client of ontology")
	}
	data, err := client.GetSmartContract(this.getNextQid(), contractAddress)
	if err != nil {
		return nil, err
	}
	deployCode, err := utils.GetSmartContract(data)
	if err != nil {
		return nil, err
	}
	sm := sdkcom.SmartContract(*deployCode)
	return &sm, nil
}

func (this *OntologySdk) GetSmartContractEvent(txHash string) (*sdkcom.SmartContactEvent, error) {
	client := this.getClient()
	if client == nil {
		return nil, fmt.Errorf("don't have available client of ontology")
	}
	data, err := client.GetSmartContractEvent(this.getNextQid(), txHash)
	if err != nil {
		return nil, err
	}
	return utils.GetSmartContractEvent(data)
}

func (this *OntologySdk) GetSmartContractEventByBlock(height uint32) ([]*sdkcom.SmartContactEvent, error) {
	client := this.getClient()
	if client == nil {
		return nil, fmt.Errorf("don't have available client of ontology")
	}
	data, err := client.GetSmartContractEventByBlock(this.getNextQid(), height)
	if err != nil {
		return nil, err
	}
	return utils.GetSmartContactEvents(data)
}

func (this *OntologySdk) GetGenerateBlockTime() (uint32, error) {
	client := this.getClient()
	if client == nil {
		return 0, fmt.Errorf("don't have available client of ontology")
	}
	data, err := client.GetGenerateBlockTime(this.getNextQid())
	if err != nil {
		return 0, err
	}
	return utils.GetUint32(data)
}

func (this *OntologySdk) GetMerkleProof(txHash string) (*sdkcom.MerkleProof, error) {
	client := this.getClient()
	if client == nil {
		return nil, fmt.Errorf("don't have available client of ontology")
	}
	data, err := client.GetMerkleProof(this.getNextQid(), txHash)
	if err != nil {
		return nil, err
	}
	return utils.GetMerkleProof(data)
}

func (this *OntologySdk) GetMemPoolTxState(txHash string) (*sdkcom.MemPoolTxState, error) {
	client := this.getClient()
	if client == nil {
		return nil, fmt.Errorf("don't have available client of ontology")
	}
	data, err := client.GetMemPoolTxState(this.getNextQid(), txHash)
	if err != nil {
		return nil, err
	}
	return utils.GetMemPoolTxState(data)
}

func (this *OntologySdk) GetMemPoolTxCount() (*sdkcom.MemPoolTxCount, error) {
	client := this.getClient()
	if client == nil {
		return nil, fmt.Errorf("don't have available client of ontology")
	}
	data, err := client.GetMemPoolTxCount(this.getNextQid())
	if err != nil {
		return nil, err
	}
	return utils.GetMemPoolTxCount(data)
}

func (this *OntologySdk) GetVersion() (string, error) {
	client := this.getClient()
	if client == nil {
		return "", fmt.Errorf("don't have available client of ontology")
	}
	data, err := client.GetVersion(this.getNextQid())
	if err != nil {
		return "", err
	}
	return utils.GetVersion(data)
}

func (this *OntologySdk) GetNetworkId() (uint32, error) {
	client := this.getClient()
	if client == nil {
		return 0, fmt.Errorf("don't have available client of ontology")
	}
	data, err := client.GetNetworkId(this.getNextQid())
	if err != nil {
		return 0, err
	}
	return utils.GetUint32(data)
}

func (this *OntologySdk) SendTransaction(tx *types.Transaction) (common.Uint256, error) {
	client := this.getClient()
	if client == nil {
		return common.UINT256_EMPTY, fmt.Errorf("don't have available client of ontology")
	}
	data, err := client.SendRawTransaction(this.getNextQid(), tx, false)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	return utils.GetUint256(data)
}

func (this *OntologySdk) PreExecTransaction(tx *types.Transaction) (*sdkcom.PreExecResult, error) {
	client := this.getClient()
	if client == nil {
		return nil, fmt.Errorf("don't have available client of ontology")
	}
	data, err := client.SendRawTransaction(this.getNextQid(), tx, true)
	if err != nil {
		return nil, err
	}
	preResult := &sdkcom.PreExecResult{}
	err = json.Unmarshal(data, &preResult)
	if err != nil {
		return nil, fmt.Errorf("json.Unmarshal PreExecResult:%s error:%s", data, err)
	}
	return preResult, nil
}

func (this *OntologySdk) SignToTransaction(tx *types.Transaction, signer *account.Account) error {
	return sdkcom.SignToTransaction(tx, signer)
}

func (this *OntologySdk) MultiSignToTransaction(tx *types.Transaction, m uint16, pubKeys []keypair.PublicKey, signer *account.Account) error {
	return sdkcom.MultiSignToTransaction(tx, m, pubKeys, signer)
}

func (this *OntologySdk) NewDeployCodeTransaction(gasPrice, gasLimit uint64, contract *sdkcom.SmartContract) *types.Transaction {
	return sdkcom.NewDeployCodeTransaction(gasPrice, gasLimit,
		contract.Code,
		contract.NeedStorage,
		contract.Name,
		contract.Version,
		contract.Author,
		contract.Email,
		contract.Description)
}

func (this *OntologySdk) NewInvokeTransaction(gasPrice, gasLimit uint64, invokeCode []byte) *types.Transaction {
	return sdkcom.NewInvokeTransaction(gasPrice, gasLimit, invokeCode)
}

func (this *OntologySdk) NewNativeInvokeTransaction(
	gasPrice,
	gasLimit uint64,
	version byte,
	contractAddress common.Address,
	method string,
	params []interface{},
) (*types.Transaction, error) {
	return utils.NewNativeInvokeTransaction(gasPrice, gasLimit, version, contractAddress, method, params)
}

func (this *OntologySdk) NewNeoVMInvokeTransaction(
	gasPrice,
	gasLimit uint64,
	contractAddress common.Address,
	params []interface{},
) (*types.Transaction, error) {
	return utils.NewNeoVMInvokeTransaction(gasPrice, gasLimit, contractAddress, params)
}

//DeploySmartContract Deploy smart contract to ontology
func (this *OntologySdk) DeploySmartContract(
	gasPrice,
	gasLimit uint64,
	singer *account.Account,
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
	tx := this.NewDeployCodeTransaction(gasPrice, gasLimit, &sdkcom.SmartContract{
		Code:        invokeCode,
		NeedStorage: needStorage,
		Name:        name,
		Version:     version,
		Author:      author,
		Email:       email,
		Description: desc,
	})
	err = this.SignToTransaction(tx, singer)
	if err != nil {
		return common.Uint256{}, err
	}
	txHash, err := this.SendTransaction(tx)
	if err != nil {
		return common.Uint256{}, fmt.Errorf("SendRawTransaction error:%s", err)
	}
	return txHash, nil
}

func (this *OntologySdk) InvokeNativeContract(
	gasPrice,
	gasLimit uint64,
	singer *account.Account,
	version byte,
	contractAddress common.Address,
	method string,
	params []interface{},
) (common.Uint256, error) {
	tx, err := this.NewNativeInvokeTransaction(gasPrice, gasLimit, version, contractAddress, method, params)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	err = this.SignToTransaction(tx, singer)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	return this.SendTransaction(tx)
}

func (this *OntologySdk) PreExecInvokeNativeContract(
	contractAddress common.Address,
	version byte,
	method string,
	params []interface{},
) (*sdkcom.PreExecResult, error) {
	tx, err := this.NewNativeInvokeTransaction(0, 0, version, contractAddress, method, params)
	if err != nil {
		return nil, err
	}
	return this.PreExecTransaction(tx)
}

//Invoke neo vm smart contract.
func (this *OntologySdk) InvokeNeoVMContract(
	gasPrice,
	gasLimit uint64,
	signer *account.Account,
	contractAddress common.Address,
	params []interface{}) (common.Uint256, error) {
	tx, err := this.NewNeoVMInvokeTransaction(gasPrice, gasLimit, contractAddress, params)
	if err != nil {
		return common.UINT256_EMPTY, fmt.Errorf("NewNeoVMInvokeTransaction error:%s", err)
	}
	err = this.SignToTransaction(tx, signer)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	return this.SendTransaction(tx)
}

func (this *OntologySdk) PreExecInvokeNeoVMContract(contractAddress common.Address, params []interface{}) (*sdkcom.PreExecResult, error) {
	tx, err := this.NewNeoVMInvokeTransaction(0, 0, contractAddress, params)
	if err != nil {
		return nil, err
	}
	return this.PreExecTransaction(tx)
}

func (this *OntologySdk) getClient() sdkcom.OntologyClient {
	if this.defClient != nil {
		return this.defClient
	}
	if this.Rpc != nil {
		return this.Rpc
	}
	if this.Rest != nil {
		return this.Rest
	}
	if this.Ws != nil {
		return this.Ws
	}
	return nil
}

func (this *OntologySdk) getNextQid() string {
	return fmt.Sprintf("%d", atomic.AddUint64(&this.qid, 1))
}
