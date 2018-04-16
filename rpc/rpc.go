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
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/big"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/ontio/ontology-crypto/keypair"
	sig "github.com/ontio/ontology-crypto/signature"
	"github.com/ontio/ontology/account"
	"github.com/ontio/ontology/common"
	"github.com/ontio/ontology/common/serialization"
	"github.com/ontio/ontology/core/genesis"
	"github.com/ontio/ontology/core/payload"
	"github.com/ontio/ontology/core/types"
	"github.com/ontio/ontology/smartcontract/service/native/states"
	"github.com/ontio/ontology/smartcontract/service/wasmvm"
	cstates "github.com/ontio/ontology/smartcontract/states"
	"github.com/ontio/ontology/vm/neovm"
	vmtypes "github.com/ontio/ontology/smartcontract/types"
	"github.com/ontio/ontology/vm/wasmvm/exec"

	sdkcom "github.com/ontio/ontology-go-sdk/common"
	"github.com/ontio/ontology-go-sdk/utils"
)

//RpcClient for ontology rpc api
type RpcClient struct {
	cryptScheme string
	qid         uint64
	addr        string
	wsAddr      string
	wsClient    *utils.WebSocketClient
	httpClient  *http.Client
}

//NewRpcClient return RpcClient instance
func NewRpcClient(cryptScheme string) *RpcClient {
	return &RpcClient{
		cryptScheme: cryptScheme, //used for crypt sig
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

//SetCryptScheme set cryptScheme for crypt
func (this *RpcClient) SetCryptScheme(cryptScheme string) {
	this.cryptScheme = cryptScheme
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

//SetAddress set web socket server address. Simple http://localhost:20334
func (this *RpcClient) SetWebSocketAddress(wsAddr string) {
	this.wsAddr = wsAddr
}

//GetVersion return the version of ontology
func (this *RpcClient) GetVersion() (int, error) {
	data, err := this.sendRpcRequest(RPC_GET_VERSION, []interface{}{})
	if err != nil {
		return 0, fmt.Errorf("sendRpcRequest error:%s", err)
	}
	version := 0
	err = json.Unmarshal(data, &version)
	if err != nil {
		return 0, fmt.Errorf("json.Unmarshal:%s error:%s", data, err)
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
	ongAppove, ok := new(big.Int).SetString(balanceRsp.OngAppove, 10)
	return &sdkcom.Balance{
		Ont:       ont,
		Ong:       ong,
		OngAppove: ongAppove,
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
func (this *RpcClient) GetSmartContractEvent(txHash common.Uint256) ([]*sdkcom.SmartContactEvent, error) {
	return this.GetSmartContractEventWithHexString(hex.EncodeToString(txHash.ToArray()))
}

//GetSmartContractEvent return smart contract event execute by invoke transaction by hex string code
func (this *RpcClient) GetSmartContractEventWithHexString(txHash string) ([]*sdkcom.SmartContactEvent, error) {
	data, err := this.sendRpcRequest(RPC_GET_SMART_CONTRACT_EVENT, []interface{}{txHash})
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
func (this *RpcClient) Transfer(token string, from, to *account.Account, amount *big.Int) (common.Uint256, error) {
	var contractAddress common.Address
	switch strings.ToUpper(token) {
	case "ONT":
		contractAddress = genesis.OntContractAddress
	case "ONG":
		contractAddress = genesis.OngContractAddress
	default:
		return common.Uint256{}, fmt.Errorf("token:%s not equal ont or ong", token)
	}

	buf := bytes.NewBuffer(nil)
	var sts []*states.State
	sts = append(sts, &states.State{
		From:  from.Address,
		To:    to.Address,
		Value: amount,
	})
	transfers := &states.Transfers{
		States: sts,
	}
	err := transfers.Serialize(buf)
	if err != nil {
		return common.Uint256{}, fmt.Errorf("transfers.Serialize error %s", err)
	}
	crt := &cstates.Contract{
		Address: contractAddress,
		Method:  "transfer",
		Args:    buf.Bytes(),
	}
	buf = bytes.NewBuffer(nil)
	err = crt.Serialize(buf)
	if err != nil {
		return common.Uint256{}, fmt.Errorf("Serialize contract error:%s", err)
	}

	invokeTx := this.NewInvokeTransaction(new(big.Int).SetInt64(0), vmtypes.Native, buf.Bytes())
	err = this.SignTransaction(invokeTx, from)
	if err != nil {
		return common.Uint256{}, fmt.Errorf("SignTransaction error:%s", err)
	}
	txHash, err := this.SendRawTransaction(invokeTx)
	if err != nil {
		return common.Uint256{}, fmt.Errorf("SendTransaction error:%s", err)
	}
	return txHash, nil
}

//DeploySmartContract Deploy smart contract to ontology
func (this *RpcClient) DeploySmartContract(
	singer *account.Account,
	vmType vmtypes.VmType,
	needStorage bool,
	code,
	name,
	version,
	author,
	email,
	desc string) (common.Uint256, error) {

	c, err := hex.DecodeString(code)
	if err != nil {
		return common.Uint256{}, fmt.Errorf("hex.DecodeString error:%s", err)
	}
	tx := this.NewDeployCodeTransaction(vmType, c, needStorage, name, version, author, email, desc)

	err = this.SignTransaction(tx, singer)
	if err != nil {
		return common.Uint256{}, err
	}
	txHash, err := this.SendRawTransaction(tx)
	if err != nil {
		return common.Uint256{}, fmt.Errorf("SendRawTransaction error:%s", err)
	}
	return txHash, nil
}

//Sign sign return the signature to the data of private key
func (this *RpcClient) sign(data []byte, signer *account.Account) ([]byte, error) {
	scheme, err := sig.GetScheme(this.cryptScheme)
	if err != nil {
		return nil, fmt.Errorf("GetScheme by:%s error:%s", this.cryptScheme, err)
	}
	s, err := sig.Sign(scheme, signer.PrivateKey, data, nil)
	if err != nil {
		return nil, err
	}
	sigData, err := sig.Serialize(s)
	if err != nil {
		return nil, fmt.Errorf("sig.Serialize error:%s", err)
	}
	return sigData, nil
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
func (this *RpcClient) InvokeWasmVMSmartContract(
	siger *account.Account,
	gasLimit *big.Int,
	smartcodeAddress common.Address,
	methodName string,
	paramType wasmvm.ParamType,
	version byte,
	params []interface{}) (common.Uint256, error) {

	contract := &cstates.Contract{}
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
	tx := this.NewInvokeTransaction(new(big.Int), vmtypes.WASMVM, bf.Bytes())
	err = this.SignTransaction(tx, siger)
	if err != nil {
		return common.Uint256{}, nil
	}
	return this.SendRawTransaction(tx)
}

//buildNeoVMParamInter build neovm invoke param code
func (this *RpcClient) buildNeoVMParamInter(builder *neovm.ParamsBuilder, smartContractParams []interface{}) error {
	//VM load params in reverse order
	for i := len(smartContractParams) - 1; i >= 0; i-- {
		switch v := smartContractParams[i].(type) {
		case bool:
			builder.EmitPushBool(v)
		case int:
			builder.EmitPushInteger(big.NewInt(int64(v)))
		case uint:
			builder.EmitPushInteger(big.NewInt(int64(v)))
		case int32:
			builder.EmitPushInteger(big.NewInt(int64(v)))
		case uint32:
			builder.EmitPushInteger(big.NewInt(int64(v)))
		case int64:
			builder.EmitPushInteger(big.NewInt(int64(v)))
		case common.Fixed64:
			builder.EmitPushInteger(big.NewInt(int64(v.GetData())))
		case uint64:
			val := big.NewInt(0)
			builder.EmitPushInteger(val.SetUint64(uint64(v)))
		case string:
			builder.EmitPushByteArray([]byte(v))
		case *big.Int:
			builder.EmitPushInteger(v)
		case []byte:
			builder.EmitPushByteArray(v)
		case []interface{}:
			err := this.buildNeoVMParamInter(builder, v)
			if err != nil {
				return err
			}
			builder.EmitPushInteger(big.NewInt(int64(len(v))))
			builder.Emit(neovm.PACK)
		default:
			return fmt.Errorf("unsupported param:%s", v)
		}
	}
	return nil
}

//BuildNeoVMInvokeCode build NeoVM Invoke code for params
func (this *RpcClient) BuildNeoVMInvokeCode(smartContractAddress common.Address, params []interface{}) ([]byte, error) {
	builder := neovm.NewParamsBuilder(new(bytes.Buffer))
	err := this.buildNeoVMParamInter(builder, params)
	if err != nil {
		return nil, err
	}
	args := builder.ToArray()

	crt := &cstates.Contract{
		Address: smartContractAddress,
		Args:    args,
	}
	crtBuf := bytes.NewBuffer(nil)
	err = crt.Serialize(crtBuf)
	if err != nil {
		return nil, fmt.Errorf("Serialize contract error:%s", err)
	}

	buf := bytes.NewBuffer(nil)
	buf.Write(append([]byte{0x67}, crtBuf.Bytes()[:]...))
	return buf.Bytes(), nil
}

//Invoke neo vm smart contract. if isPreExec is true, the invoke will not really execute
func (this *RpcClient) InvokeNeoVMSmartContract(
	siger *account.Account,
	gasLimit *big.Int,
	smartcodeAddress common.Address,
	params []interface{}) (common.Uint256, error) {
	code, err := this.BuildNeoVMInvokeCode(smartcodeAddress, params)
	if err != nil {
		return common.Uint256{}, fmt.Errorf("BuildNVMInvokeCode error:%s", err)
	}
	tx := this.NewInvokeTransaction(gasLimit, vmtypes.NEOVM, code)
	err = this.SignTransaction(tx, siger)
	if err != nil {
		return common.Uint256{}, nil
	}
	return this.SendRawTransaction(tx)
}

//PrepareInvokeNeoVMSmartContract return the vm execute result of smart contract but not commit into ledger.
//It's useful for debugging smart contract.
func (this *RpcClient) PrepareInvokeNeoVMSmartContract(
	gasLimit *big.Int,
	smartcodeAddress common.Address,
	params []interface{},
	returnType sdkcom.NeoVMReturnType,
) (interface{}, error) {
	code, err := this.BuildNeoVMInvokeCode(smartcodeAddress, params)
	if err != nil {
		return nil, fmt.Errorf("BuildNVMInvokeCode error:%s", err)
	}
	tx := this.NewInvokeTransaction(gasLimit, vmtypes.NEOVM, code)

	var buffer bytes.Buffer
	err = tx.Serialize(&buffer)
	if err != nil {
		return nil, fmt.Errorf("Serialize error:%s", err)
	}
	txData := hex.EncodeToString(buffer.Bytes())
	data, err := this.sendRpcRequest(RPC_SEND_TRANSACTION, []interface{}{txData, 1})
	if err != nil {
		return nil, fmt.Errorf("sendRpcRequest error:%s", err)
	}
	var res interface{}
	err = json.Unmarshal(data, &res)
	if err != nil {
		return nil, fmt.Errorf("json.Unmarshal error:%s", err)
	}
	v, err := utils.ParseNeoVMSmartContractReturnType(res, returnType)
	if err != nil {
		return nil, fmt.Errorf("ParseNeoVMSmartContractReturnType error:%s", err)
	}
	return v, nil
}

//Sign to a transaction
func (this *RpcClient) SignTransaction(tx *types.Transaction, signer *account.Account) error {
	txHash := tx.Hash()
	sigData, err := this.sign(txHash.ToArray(), signer)
	if err != nil {
		return fmt.Errorf("sign error:%s", err)
	}
	sig := &types.Sig{
		PubKeys: []keypair.PublicKey{signer.PublicKey},
		M:       1,
		SigData: [][]byte{sigData},
	}
	tx.Sigs = []*types.Sig{sig}
	return nil
}

//MultiSignTransaction multi sign to a transaction
func (this *RpcClient) MultiSignTransaction(tx *types.Transaction, m uint8, signers []*account.Account) error {
	if len(signers) == 0 {
		return fmt.Errorf("not enough signer")
	}
	n := len(signers)
	if int(m) > n {
		return fmt.Errorf("M:%d should smaller than N:%d", m, n)
	}
	txHash := tx.Hash()
	pks := make([]keypair.PublicKey, 0, n)
	sigData := make([][]byte, 0, m)

	for i := 0; i < n; i++ {
		signer := signers[i]
		if i < int(m) {
			sig, err := this.sign(txHash.ToArray(), signer)
			if err != nil {
				return fmt.Errorf("sign error:%s", err)
			}
			sigData = append(sigData, sig)
		}
		pks = append(pks, signer.PublicKey)
	}
	sig := &types.Sig{
		PubKeys: pks,
		M:       m,
		SigData: sigData,
	}
	tx.Sigs = []*types.Sig{sig}
	return nil
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

//NewDeployCodeTransaction return a smart contract deploy transaction instance
func (this *RpcClient) NewDeployCodeTransaction(
	vmType vmtypes.VmType,
	code []byte,
	needStorage bool,
	name, version, author, email, desc string) *types.Transaction {

	vmCode := vmtypes.VmCode{
		VmType: vmType,
		Code:   code,
	}
	deployPayload := &payload.DeployCode{
		Code:        vmCode,
		NeedStorage: needStorage,
		Name:        name,
		Version:     version,
		Author:      author,
		Email:       email,
		Description: desc,
	}
	tx := &types.Transaction{
		Version:    0,
		TxType:     types.Deploy,
		Nonce:      uint32(time.Now().Unix()),
		Payload:    deployPayload,
		Attributes: make([]*types.TxAttribute, 0, 0),
		Fee:        make([]*types.Fee, 0, 0),
		NetWorkFee: 0,
		Sigs:       make([]*types.Sig, 0, 0),
	}
	return tx
}

//NewInvokeTransaction return smart contract invoke transaction
func (this *RpcClient) NewInvokeTransaction(gasLimit *big.Int, vmType vmtypes.VmType, code []byte) *types.Transaction {
	invokePayload := &payload.InvokeCode{
		GasLimit: common.Fixed64(gasLimit.Int64()),
		Code: vmtypes.VmCode{
			VmType: vmType,
			Code:   code,
		},
	}
	tx := &types.Transaction{
		Version:    0,
		TxType:     types.Invoke,
		Nonce:      uint32(time.Now().Unix()),
		Payload:    invokePayload,
		Attributes: make([]*types.TxAttribute, 0, 0),
		Fee:        make([]*types.Fee, 0, 0),
		NetWorkFee: 0,
		Sigs:       make([]*types.Sig, 0, 0),
	}
	return tx
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
		return nil, fmt.Errorf("sendRpcRequest error code:%d desc:%s", rpcRsp.Error, rpcRsp.Desc)
	}
	return rpcRsp.Result, nil
}
