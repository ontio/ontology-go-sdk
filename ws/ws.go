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
package ws

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
	nutils "github.com/ontio/ontology/smartcontract/service/native/utils"
	cstates "github.com/ontio/ontology/smartcontract/states"
	"math/big"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

type WSClient struct {
	qid               uint64
	addr              string
	subStatus         *WSSubscribeStatus
	ws                *utils.WebSocketClient
	reqMap            map[string]*WSRequest
	recvCh            chan []byte
	actionCh          chan *WSAction
	exitCh            chan interface{}
	lastHeartbeatTime time.Time
	lock              sync.RWMutex
}

func NewWSClient() *WSClient {
	wsClient := &WSClient{
		subStatus: &WSSubscribeStatus{},
		ws:        utils.NewWebSocketClient(),
		reqMap:    make(map[string]*WSRequest),
		recvCh:    make(chan []byte, WS_RECV_CHAN_SIZE),
		actionCh:  make(chan *WSAction, WS_RECV_CHAN_SIZE),
		exitCh:    make(chan interface{}, 0),
	}
	wsClient.ws.OnMessage = wsClient.onMessage
	wsClient.ws.OnError = wsClient.onError
	wsClient.ws.OnConnect = wsClient.onConnect
	wsClient.ws.OnClose = wsClient.onClose
	return wsClient
}

func (this *WSClient) Connect(address string) error {
	this.addr = address
	err := this.ws.Connect(address)
	if err != nil {
		return err
	}
	go this.start()
	return nil
}

func (this *WSClient) updateLastHeartbeatTime() {
	this.lock.Lock()
	defer this.lock.Unlock()
	this.lastHeartbeatTime = time.Now()
}

func (this *WSClient) getLastHeartbeatTime() time.Time {
	this.lock.RLock()
	defer this.lock.RUnlock()
	return this.lastHeartbeatTime
}

func (this *WSClient) SetOnConnect(f func(address string)) {
	this.ws.OnConnect = f
}

func (this *WSClient) SetOnClose(f func(address string)) {
	this.ws.OnClose = f
}

func (this *WSClient) SetOnError(f func(address string, err error)) {
	this.ws.OnError = f
}

func (this *WSClient) onMessage(data []byte) {
	this.updateLastHeartbeatTime()
	this.recvCh <- data
}

func (this *WSClient) onError(address string, err error) {
	fmt.Printf("WSClient OnError address:%s error:%s\n", address, err)
}

func (this *WSClient) onConnect(address string) {
	fmt.Printf("WSClient OnConnect address:%s connect success\n", address)
}

func (this *WSClient) onClose(address string) {
	fmt.Printf("WSClient OnClose address:%s close success\n", address)
}

func (this *WSClient) start() {
	heartbeatTimer := time.NewTicker(time.Second)
	defer heartbeatTimer.Stop()
	for {
		select {
		case <-this.exitCh:
			return
		case <-heartbeatTimer.C:
			if int(time.Now().Sub(this.getLastHeartbeatTime()).Seconds()) >= WS_HEARTBEAT_INTERVAL {
				this.sendHeartbeat()
			}
		case data := <-this.recvCh:
			wsResp := &WSResponse{}
			err := json.Unmarshal(data, wsResp)
			if err != nil {
				this.ws.OnError(this.addr, fmt.Errorf("json.Unmarshal WSResponse error:%s", err))
			} else {
				go this.onAction(wsResp)
			}
		}
	}
}

func (this *WSClient) onAction(resp *WSResponse) {
	if resp.Id == "" {
		switch resp.Action {
		case WS_SUB_ACTION_RAW_BLOCK:
			this.onRawBlockAction(resp)
		case WS_SUB_ACTION_BLOCK_TX_HASH:
			this.onBlockTxHashesAction(resp)
		case WS_SUB_ACTION_NOTIFY:
			this.onSmartcontractEventAction(resp)
		case WS_SUB_ACTION_LOG:
			this.onSmartcontractEventLogAction(resp)
		default:
			this.ws.OnError(this.addr, fmt.Errorf("unknown subscribe action:%s", resp.Action))
		}
		return
	}
	req := this.getReq(resp.Id)
	if req == nil {
		return
	}
	req.ResCh <- resp
	this.delReq(resp.Id)
}

func (this *WSClient) onRawBlockAction(resp *WSResponse) {
	block, err := utils.GetBlock(resp.Result)
	if err != nil {
		this.ws.OnError(this.addr, fmt.Errorf("onRawBlockAction error:%s", err))
		return
	}
	this.actionCh <- &WSAction{
		Action: WS_SUBSCRIBE_ACTION_BLOCK,
		Result: block,
	}
}

func (this *WSClient) onBlockTxHashesAction(resp *WSResponse) {
	blockTxHashes, err := utils.GetBlockTxHashes(resp.Result)
	if err != nil {
		this.ws.OnError(this.addr, fmt.Errorf("onBlockTxHashesAction error:%s", err))
		return
	}
	this.actionCh <- &WSAction{
		Action: WS_SUBSCRIBE_ACTION_BLOCK_TX_HASH,
		Result: blockTxHashes,
	}
}

func (this *WSClient) onSmartcontractEventAction(resp *WSResponse) {
	event, err := utils.GetSmartContractEvent(resp.Result)
	if err != nil {
		this.ws.OnError(this.addr, fmt.Errorf("onSmartcontractEventAction error:%s", err))
		return
	}
	this.actionCh <- &WSAction{
		Action: WS_SUBSCRIBE_ACTION_EVENT_NOTIFY,
		Result: event,
	}
}

func (this *WSClient) onSmartcontractEventLogAction(resp *WSResponse) {
	log, err := utils.GetSmartContractEventLog(resp.Result)
	if err != nil {
		this.ws.OnError(this.addr, fmt.Errorf("onSmartcontractEventLogAction error:%s", err))
		return
	}
	this.actionCh <- &WSAction{
		Action: WS_SUBSCRIBE_ACTION_EVENT_LOG,
		Result: log,
	}
}

func (this *WSClient) AddContractFilter(contractAddress common.Address, timeout ...time.Duration) error {
	return this.AddContractFilterWithHexString(contractAddress.ToHexString(), timeout...)
}

func (this *WSClient) AddContractFilterWithHexString(contractAddress string, timeout ...time.Duration) error {
	if this.subStatus.HasContractFilter(contractAddress) {
		return nil
	}
	this.subStatus.AddContractFilter(contractAddress)
	_, err := this.sendSyncWSRequest(WS_ACTION_SUBSCRIBE, map[string]interface{}{
		WS_SUB_CONTRACT_FILTER: this.subStatus.GetContractFilter(),
		WS_SUB_EVENT:           this.subStatus.SubscribeEvent,
		WS_SUB_JSON_BLOCK:      this.subStatus.SubscribeJsonBlock,
		WS_SUB_RAW_BLOCK:       this.subStatus.SubscribeRawBlock,
		WS_SUB_BLOCK_TX_HASH:   this.subStatus.SubscribeBlockTxHashs,
	}, timeout...)
	if err != nil {
		this.subStatus.DelContractFilter(contractAddress)
		return err
	}
	return nil
}

func (this *WSClient) DelContractFilter(contractAddress common.Address, timeout ...time.Duration) error {
	return this.DelContractFilterWithHexString(contractAddress.ToHexString(), timeout...)
}

func (this *WSClient) DelContractFilterWithHexString(contractAddress string, timeout ...time.Duration) error {
	if !this.subStatus.HasContractFilter(contractAddress) {
		return nil
	}
	this.subStatus.DelContractFilter(contractAddress)
	_, err := this.sendSyncWSRequest(WS_ACTION_SUBSCRIBE, map[string]interface{}{
		WS_SUB_CONTRACT_FILTER: this.subStatus.GetContractFilter(),
		WS_SUB_EVENT:           this.subStatus.SubscribeEvent,
		WS_SUB_JSON_BLOCK:      this.subStatus.SubscribeJsonBlock,
		WS_SUB_RAW_BLOCK:       this.subStatus.SubscribeRawBlock,
		WS_SUB_BLOCK_TX_HASH:   this.subStatus.SubscribeBlockTxHashs,
	}, timeout...)
	if err != nil {
		this.subStatus.AddContractFilter(contractAddress)
		return err
	}
	return nil
}

func (this *WSClient) SubscribeBlock(timeout ...time.Duration) error {
	if this.subStatus.SubscribeRawBlock {
		return nil
	}
	_, err := this.sendSyncWSRequest(WS_ACTION_SUBSCRIBE, map[string]interface{}{
		WS_SUB_CONTRACT_FILTER: this.subStatus.GetContractFilter(),
		WS_SUB_EVENT:           this.subStatus.SubscribeEvent,
		WS_SUB_JSON_BLOCK:      this.subStatus.SubscribeJsonBlock,
		WS_SUB_RAW_BLOCK:       true,
		WS_SUB_BLOCK_TX_HASH:   this.subStatus.SubscribeBlockTxHashs,
	}, timeout...)
	if err != nil {
		return err
	}
	this.subStatus.SubscribeRawBlock = true
	return nil
}

func (this *WSClient) UnsubscribeBlock(timeout ...time.Duration) error {
	if !this.subStatus.SubscribeRawBlock {
		return nil
	}
	_, err := this.sendSyncWSRequest(WS_ACTION_SUBSCRIBE, map[string]interface{}{
		WS_SUB_CONTRACT_FILTER: this.subStatus.GetContractFilter(),
		WS_SUB_EVENT:           this.subStatus.SubscribeEvent,
		WS_SUB_JSON_BLOCK:      this.subStatus.SubscribeJsonBlock,
		WS_SUB_RAW_BLOCK:       false,
		WS_SUB_BLOCK_TX_HASH:   this.subStatus.SubscribeBlockTxHashs,
	}, timeout...)
	if err != nil {
		return err
	}
	this.subStatus.SubscribeRawBlock = false
	return nil
}

func (this *WSClient) SubscribeEvent(timeout ...time.Duration) error {
	if this.subStatus.SubscribeEvent {
		return nil
	}
	_, err := this.sendSyncWSRequest(WS_ACTION_SUBSCRIBE, map[string]interface{}{
		WS_SUB_CONTRACT_FILTER: this.subStatus.GetContractFilter(),
		WS_SUB_EVENT:           true,
		WS_SUB_JSON_BLOCK:      this.subStatus.SubscribeJsonBlock,
		WS_SUB_RAW_BLOCK:       this.subStatus.SubscribeRawBlock,
		WS_SUB_BLOCK_TX_HASH:   this.subStatus.SubscribeBlockTxHashs,
	}, timeout...)
	if err != nil {
		return err
	}
	this.subStatus.SubscribeEvent = true
	return nil
}

func (this *WSClient) UnsubscribeEvent(timeout ...time.Duration) error {
	if !this.subStatus.SubscribeEvent {
		return nil
	}
	_, err := this.sendSyncWSRequest(WS_ACTION_SUBSCRIBE, map[string]interface{}{
		WS_SUB_CONTRACT_FILTER: this.subStatus.GetContractFilter(),
		WS_SUB_EVENT:           false,
		WS_SUB_JSON_BLOCK:      this.subStatus.SubscribeJsonBlock,
		WS_SUB_RAW_BLOCK:       this.subStatus.SubscribeRawBlock,
		WS_SUB_BLOCK_TX_HASH:   this.subStatus.SubscribeBlockTxHashs,
	}, timeout...)
	if err != nil {
		return err
	}
	this.subStatus.SubscribeEvent = false
	return nil
}

func (this *WSClient) SubscribeTxHash(timeout ...time.Duration) error {
	if this.subStatus.SubscribeBlockTxHashs {
		return nil
	}
	_, err := this.sendSyncWSRequest(WS_ACTION_SUBSCRIBE, map[string]interface{}{
		WS_SUB_CONTRACT_FILTER: this.subStatus.GetContractFilter(),
		WS_SUB_EVENT:           this.subStatus.SubscribeEvent,
		WS_SUB_JSON_BLOCK:      this.subStatus.SubscribeJsonBlock,
		WS_SUB_RAW_BLOCK:       this.subStatus.SubscribeRawBlock,
		WS_SUB_BLOCK_TX_HASH:   true,
	}, timeout...)
	if err != nil {
		return err
	}
	this.subStatus.SubscribeBlockTxHashs = true
	return nil
}

func (this *WSClient) UnsubscribeTxHash(timeout ...time.Duration) error {
	if !this.subStatus.SubscribeBlockTxHashs {
		return nil
	}
	_, err := this.sendSyncWSRequest(WS_ACTION_SUBSCRIBE, map[string]interface{}{
		WS_SUB_CONTRACT_FILTER: this.subStatus.GetContractFilter(),
		WS_SUB_EVENT:           this.subStatus.SubscribeEvent,
		WS_SUB_JSON_BLOCK:      this.subStatus.SubscribeJsonBlock,
		WS_SUB_RAW_BLOCK:       this.subStatus.SubscribeRawBlock,
		WS_SUB_BLOCK_TX_HASH:   false,
	}, timeout...)
	if err != nil {
		return err
	}
	this.subStatus.SubscribeBlockTxHashs = false
	return nil
}

func (this *WSClient) GetVersion(timeout ...time.Duration) (string, error) {
	data, err := this.sendSyncWSRequest(WS_ACTION_GET_VERSION, nil, timeout...)
	if err != nil {
		return "", err
	}
	var version string
	err = json.Unmarshal(data, &version)
	if err != nil {
		return "", fmt.Errorf("json.Unmarshal version error:%s", err)
	}
	return version, nil
}

func (this *WSClient) GetNetworkId(timeout ...time.Duration) (uint32, error) {
	data, err := this.sendSyncWSRequest(WS_ACTION_GET_NETWORK_ID, nil, timeout...)
	if err != nil {
		return 0, err
	}
	var networkId uint32
	err = json.Unmarshal(data, &networkId)
	if err != nil {
		return 0, fmt.Errorf("json.Unmarshal networkId error:%s", err)
	}
	return networkId, nil
}

func (this *WSClient) GetBlockByHash(hash common.Uint256, timeout ...time.Duration) (*types.Block, error) {
	return this.GetBlockByHashWithHexString(hash.ToHexString(), timeout...)
}

func (this *WSClient) GetBlockByHashWithHexString(hash string, timeout ...time.Duration) (*types.Block, error) {
	data, err := this.sendSyncWSRequest(WS_ACTION_GET_BLOCK_BY_HASH, map[string]interface{}{"Raw": "1", "Hash": hash}, timeout...)
	if err != nil {
		return nil, err
	}
	return utils.GetBlock(data)
}

func (this *WSClient) GetBlockByHeight(height uint32, timeout ...time.Duration) (*types.Block, error) {
	data, err := this.sendSyncWSRequest(WS_ACTION_GET_BLOCK_BY_HEIGHT, map[string]interface{}{"Raw": "1", "Height": height}, timeout...)
	if err != nil {
		return nil, err
	}
	return utils.GetBlock(data)
}

func (this *WSClient) GetBlockHash(height uint32, timeout ...time.Duration) (common.Uint256, error) {
	data, err := this.sendSyncWSRequest(WS_ACTION_GET_BLOCK_HASH, map[string]interface{}{"Height": height}, timeout...)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	return utils.GetUint256(data)
}

func (this *WSClient) GetRawTransaction(txHash common.Uint256, timeout ...time.Duration) (*types.Transaction, error) {
	return this.GetRawTransactionWithHexString(txHash.ToHexString(), timeout...)
}

func (this *WSClient) GetRawTransactionWithHexString(txHash string, timeout ...time.Duration) (*types.Transaction, error) {
	data, err := this.sendSyncWSRequest(WS_ACTION_GET_TRANSACTION, map[string]interface{}{"Raw": "1", "Hash": txHash}, timeout...)
	if err != nil {
		return nil, err
	}
	return utils.GetTransaction(data)
}

func (this *WSClient) SendRawTransaction(tx *types.Transaction, timeout ...time.Duration) (common.Uint256, error) {
	var buffer bytes.Buffer
	err := tx.Serialize(&buffer)
	if err != nil {
		return common.Uint256{}, fmt.Errorf("Serialize error:%s", err)
	}
	txData := hex.EncodeToString(buffer.Bytes())
	data, err := this.sendSyncWSRequest(WS_ACTION_SEND_TRANSACTION, map[string]interface{}{"Data": txData}, timeout...)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	return utils.GetUint256(data)
}

func (this *WSClient) GetMemPoolTxState(txHash common.Uint256, timeout ...time.Duration) (*sdkcom.MemPoolTxState, error) {
	return this.GetMemPoolTxStateWithHexString(txHash.ToHexString(), timeout...)
}

func (this *WSClient) GetMemPoolTxStateWithHexString(txHash string, timeout ...time.Duration) (*sdkcom.MemPoolTxState, error) {
	data, err := this.sendSyncWSRequest(WS_ACTION_GET_MEM_POOL_TX_STATE, map[string]interface{}{"Hash": txHash}, timeout...)
	if err != nil {
		return nil, err
	}
	return utils.GetMemPoolTxState(data)
}

func (this *WSClient) GetMemPoolTxCount(timeout ...time.Duration) (*sdkcom.MemPoolTxCount, error) {
	data, err := this.sendSyncWSRequest(WS_ACTION_GET_MEM_POOL_TX_COUNT, nil, timeout...)
	if err != nil {
		return nil, err
	}
	return utils.GetMemPoolTxCount(data)
}

func (this *WSClient) GetCurrentBlockHeight(timeout ...time.Duration) (uint32, error) {
	data, err := this.sendSyncWSRequest(WS_ACTION_GET_BLOCK_HEIGHT, nil, timeout...)
	if err != nil {
		return 0, err
	}
	return utils.GetUint32(data)
}

func (this *WSClient) GetCurrentBlockHash(timeout ...time.Duration) (common.Uint256, error) {
	curBlockHeight, err := this.GetCurrentBlockHeight(timeout...)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	return this.GetBlockHash(curBlockHeight, timeout...)
}

func (this *WSClient) GetBlockHeightByTxHash(txHash common.Uint256, timeout ...time.Duration) (uint32, error) {
	return this.GetBlockHeightByTxHashWithHexString(txHash.ToHexString(), timeout...)
}

func (this *WSClient) GetBlockHeightByTxHashWithHexString(txHash string, timeout ...time.Duration) (uint32, error) {
	data, err := this.sendSyncWSRequest(WS_ACTION_GET_BLOCK_HEIGHT_BY_TX_HASH, map[string]interface{}{"Hash": txHash}, timeout...)
	if err != nil {
		return 0, err
	}
	return utils.GetUint32(data)
}

func (this *WSClient) GetBlockTxHashesByHeight(height uint32, timeout ...time.Duration) (*sdkcom.BlockTxHashes, error) {
	data, err := this.sendSyncWSRequest(WS_ACTION_GET_BLOCK_TX_HASH_BY_HEIGHT, map[string]interface{}{"Height": height}, timeout...)
	if err != nil {
		return nil, err
	}
	return utils.GetBlockTxHashes(data)
}

func (this *WSClient) GetStorage(contractAddress common.Address, key []byte, timeout ...time.Duration) ([]byte, error) {
	data, err := this.sendSyncWSRequest(WS_ACTION_GET_STORAGE, map[string]interface{}{"Hash": contractAddress.ToHexString(), "Key": hex.EncodeToString(key)}, timeout...)
	if err != nil {
		return nil, err
	}
	return utils.GetStorage(data)
}

func (this *WSClient) GetSmartContract(contractAddress common.Address, timeout ...time.Duration) (*payload.DeployCode, error) {
	return this.GetSmartContractWithHexString(contractAddress.ToHexString(), timeout...)
}

func (this *WSClient) GetSmartContractWithHexString(contractAddress string, timeout ...time.Duration) (*payload.DeployCode, error) {
	data, err := this.sendSyncWSRequest(WS_ACTION_GET_CONTRACT, map[string]interface{}{"Hash": contractAddress, "Raw": "1"}, timeout...)
	if err != nil {
		return nil, err
	}
	return utils.GetSmartContract(data)
}

func (this *WSClient) GetMerkleProof(txHash common.Uint256, timeout ...time.Duration) (*sdkcom.MerkleProof, error) {
	return this.GetMerkleProofWithHexString(txHash.ToHexString(), timeout...)
}

func (this *WSClient) GetMerkleProofWithHexString(txHash string, timeout ...time.Duration) (*sdkcom.MerkleProof, error) {
	data, err := this.sendSyncWSRequest(WS_ACTION_GET_MERKLE_PROOF, map[string]interface{}{"Hash": txHash}, timeout...)
	if err != nil {
		return nil, err
	}
	return utils.GetMerkleProof(data)
}

func (this *WSClient) GetSmartContractEvent(txHash common.Uint256, timeout ...time.Duration) (*sdkcom.SmartContactEvent, error) {
	return this.GetSmartContractEventWithHexString(txHash.ToHexString(), timeout...)
}

func (this *WSClient) GetSmartContractEventWithHexString(txHash string, timeout ...time.Duration) (*sdkcom.SmartContactEvent, error) {
	data, err := this.sendSyncWSRequest(WS_ACTION_GET_SMARTCONTRACT_BY_HASH, map[string]interface{}{"Hash": txHash}, timeout...)
	if err != nil {
		return nil, err
	}
	return utils.GetSmartContractEvent(data)
}

func (this *WSClient) GetSmartContractEventByBlock(blockHeight uint32, timeout ...time.Duration) ([]*sdkcom.SmartContactEvent, error) {
	data, err := this.sendSyncWSRequest(WS_ACTION_GET_SMARTCONTRACT_BY_HEIGHT, map[string]interface{}{"Height": blockHeight}, timeout...)
	if err != nil {
		return nil, err
	}
	return utils.GetSmartContactEvents(data)
}

//GetBalance return ont and ong balance of a ontology account
func (this *WSClient) GetBalance(addr common.Address) (*sdkcom.Balance, error) {
	ontBalance, err := this.PrepareInvokeNativeContractWithRes(
		nutils.OntContractAddress,
		sdkcom.VERSION_CONTRACT_ONT,
		ont.BALANCEOF_NAME,
		[]interface{}{addr[:]},
		sdkcom.NEOVM_TYPE_INTEGER)
	if err != nil {
		return nil, fmt.Errorf("Get ONT balance of error:%s", err)
	}
	ongBalance, err := this.PrepareInvokeNativeContractWithRes(
		nutils.OngContractAddress,
		sdkcom.VERSION_CONTRACT_ONG,
		ont.BALANCEOF_NAME,
		[]interface{}{addr[:]},
		sdkcom.NEOVM_TYPE_INTEGER)
	if err != nil {
		return nil, fmt.Errorf("Get ONG balance of error:%s", err)
	}
	return &sdkcom.Balance{
		Ont: ontBalance.(*big.Int).Uint64(),
		Ong: ongBalance.(*big.Int).Uint64(),
	}, nil
}

//GetBalance return ont and ong balance of a ontology account in base58 code address
func (this *WSClient) GetBalanceWithBase58(base58Addr string) (*sdkcom.Balance, error) {
	addr, err := common.AddressFromBase58(base58Addr)
	if err != nil {
		return nil, fmt.Errorf("AddressFromBase58 error:%s", err)
	}
	return this.GetBalance(addr)
}

//Transfer ONT of ONG
//for ONT amount is the raw value
//for ONG amount is the raw value * 10e9
func (this *WSClient) Transfer(gasPrice,
	gasLimit uint64,
	asset string,
	from *account.Account,
	to common.Address,
	amount uint64) (common.Uint256, error) {
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

func (this *WSClient) Allowance(asset string, from, to common.Address) (uint64, error) {
	type allowanceStruct struct {
		From common.Address
		To   common.Address
	}
	contractAddress, err := utils.GetAssetAddress(asset)
	if err != nil {
		return 0, err
	}
	allowance, err := this.PrepareInvokeNativeContractWithRes(
		contractAddress,
		sdkcom.VERSION_CONTRACT_ONT,
		sdkcom.NATIVE_ALLOWANCE,
		[]interface{}{&allowanceStruct{From: from, To: to}},
		sdkcom.NEOVM_TYPE_INTEGER)
	if err != nil {
		return 0, err
	}
	return allowance.(*big.Int).Uint64(), nil
}

func (this *WSClient) Approve(gasPrice, gasLimit uint64,
	asset string,
	from *account.Account,
	to common.Address,
	amount uint64) (common.Uint256, error) {
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

func (this *WSClient) TransferFrom(gasPrice, gasLimit uint64,
	asset string,
	sender *account.Account,
	from, to common.Address,
	amount uint64) (common.Uint256, error) {
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

func (this *WSClient) UnboundONG(user common.Address) (uint64, error) {
	return this.Allowance("ong", nutils.OntContractAddress, user)
}

func (this *WSClient) WithdrawONG(gasPrice, gasLimit uint64,
	user *account.Account,
	withdrawAmount ...uint64) (common.Uint256, error) {
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
	return this.TransferFrom(gasPrice, gasLimit, "ong", user, nutils.OntContractAddress, user.Address, amount)
}

func (this *WSClient) NewTransferTransaction(gasPrice, gasLimit uint64,
	asset string,
	from, to common.Address,
	amount uint64) (*types.Transaction, error) {
	return utils.NewTransferTransaction(gasPrice, gasLimit, asset, from, to, amount)
}

func (this *WSClient) NewMultiTransferTransfer(gasPrice, gasLimit uint64, asset string, states []*ont.State) (*types.Transaction, error) {
	return utils.NewMultiTransferTransaction(gasPrice, gasLimit, asset, states)
}

func (this *WSClient) NewApproveTransaction(gasPrice, gasLimit uint64,
	asset string, from, to common.Address,
	amount uint64) (*types.Transaction, error) {
	return utils.NewApproveTransaction(gasPrice, gasLimit, asset, from, to, amount)
}

func (this *WSClient) NewTransferFromTransaction(gasPrice, gasLimit uint64,
	asset string,
	sender, from, to common.Address,
	amount uint64) (*types.Transaction, error) {
	return utils.NewTransferFromTransaction(gasPrice, gasLimit, asset, sender, from, to, amount)
}

//DeploySmartContract Deploy smart contract to ontology
func (this *WSClient) DeploySmartContract(
	gasPrice,
	gasLimit uint64,
	singer *account.Account,
	needStorage bool,
	code,
	cname,
	cversion,
	cauthor,
	cemail,
	cdesc string,
	timeout ...time.Duration) (common.Uint256, error) {

	invokeCode, err := hex.DecodeString(code)
	if err != nil {
		return common.UINT256_EMPTY, fmt.Errorf("code hex decode error:%s", err)
	}
	tx := this.NewDeployCodeTransaction(gasPrice, gasLimit, invokeCode, needStorage, cname, cversion, cauthor, cemail, cdesc)
	err = this.SignToTransaction(tx, singer)
	if err != nil {
		return common.Uint256{}, err
	}
	txHash, err := this.SendRawTransaction(tx, timeout...)
	if err != nil {
		return common.Uint256{}, fmt.Errorf("SendRawTransaction error:%s", err)
	}
	return txHash, nil
}

func (this *WSClient) InvokeNativeContract(
	gasPrice,
	gasLimit uint64,
	singer *account.Account,
	cversion byte,
	contractAddress common.Address,
	method string,
	params []interface{},
	timeout ...time.Duration,
) (common.Uint256, error) {
	tx, err := this.NewNativeInvokeTransaction(gasPrice, gasLimit, cversion, contractAddress, method, params)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	err = this.SignToTransaction(tx, singer)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	return this.SendRawTransaction(tx, timeout...)
}

//Invoke neo vm smart contract.
func (this *WSClient) InvokeNeoVMContract(
	gasPrice,
	gasLimit uint64,
	signer *account.Account,
	contractAddress common.Address,
	params []interface{},
	timeout ...time.Duration) (common.Uint256, error) {

	tx, err := this.NewNeoVMInvokeTransaction(gasPrice, gasLimit, contractAddress, params)
	if err != nil {
		return common.UINT256_EMPTY, fmt.Errorf("NewNeoVMInvokeTransaction error:%s", err)
	}
	err = this.SignToTransaction(tx, signer)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	return this.SendRawTransaction(tx, timeout...)
}

func (this *WSClient) NewDeployCodeTransaction(
	gasPrice, gasLimit uint64,
	code []byte,
	needStorage bool,
	cname, cversion, cauthor, cemail, cdesc string) *types.Transaction {
	return sdkcom.NewDeployCodeTransaction(gasPrice, gasLimit, code, needStorage, cname, cversion, cauthor, cemail, cdesc)
}

func (this *WSClient) NewNativeInvokeTransaction(gasPrice,
	gasLimit uint64,
	cversion byte,
	contractAddress common.Address,
	method string,
	params []interface{},
) (*types.Transaction, error) {
	return utils.NewNativeInvokeTransaction(gasPrice, gasLimit, cversion, contractAddress, method, params)
}

func (this *WSClient) NewNeoVMInvokeTransaction(
	gasPrice, gasLimit uint64,
	contractAddress common.Address,
	params []interface{},
) (*types.Transaction, error) {
	return utils.NewNeoVMInvokeTransaction(gasPrice, gasLimit, contractAddress, params)
}

//PrepareInvokeNeoVMContractWithRes Prepare invoke neovm contract, and return the value of result.
//Param returnType must be one of NeoVMReturnType, or array of NeoVMReturnType
func (this *WSClient) PrepareInvokeNeoVMContractWithRes(contractAddress common.Address,
	params []interface{},
	returnType interface{},
	timeout ...time.Duration) (interface{}, error) {
	preResult, err := this.PrepareInvokeNeoVMContract(contractAddress, params, timeout...)
	if err != nil {
		return nil, err
	}
	if preResult.State == 0 {
		return nil, fmt.Errorf("prepare inoke failed")
	}
	v, err := utils.ParsePreExecResult(preResult.Result, returnType)
	if err != nil {
		return nil, fmt.Errorf("ParseNeoVMContractReturnType error:%s", err)
	}
	return v, nil
}

func (this *WSClient) PrepareInvokeNeoVMContract(contractAddress common.Address,
	params []interface{}, timeout ...time.Duration) (*cstates.PreExecResult, error) {
	this.NewNeoVMInvokeTransaction(0, 0, contractAddress, params)

	tx, err := this.NewNeoVMInvokeTransaction(0, 0, contractAddress, params)
	if err != nil {
		return nil, fmt.Errorf("NewNeoVMInvokeTransaction error:%s", err)
	}
	return this.PrepareInvokeContract(tx, timeout...)
}

func (this *WSClient) PrepareInvokeNativeContract(contractAddress common.Address,
	version byte,
	method string,
	params []interface{},
	timeout ...time.Duration) (*cstates.PreExecResult, error) {
	tx, err := this.NewNativeInvokeTransaction(0, 0, version, contractAddress, method, params)
	if err != nil {
		return nil, fmt.Errorf("NewNeoVMInvokeTransaction error:%s", err)
	}
	return this.PrepareInvokeContract(tx, timeout...)
}

//PrepareInvokeNativeContractWithRes Prepare invoke native contract, and return the value of result.
//Param returnType must be one of NeoVMReturnType, or array of NeoVMReturnType
func (this *WSClient) PrepareInvokeNativeContractWithRes(contractAddress common.Address,
	version byte,
	method string,
	params []interface{},
	returnType interface{},
	timeout ...time.Duration) (interface{}, error) {
	preResult, err := this.PrepareInvokeNativeContract(contractAddress, version, method, params, timeout...)
	if err != nil {
		return nil, err
	}
	if preResult.State == 0 {
		return nil, fmt.Errorf("prepare inoke failed")
	}
	v, err := utils.ParsePreExecResult(preResult.Result, returnType)
	if err != nil {
		return nil, fmt.Errorf("ParseNeoVMContractReturnType error:%s", err)
	}
	return v, nil
}

//PrepareInvokeContract return the vm execute result of smart contract but not commit into ledger.
//It's useful for debugging smart contract.
func (this *WSClient) PrepareInvokeContract(tx *types.Transaction, timeout ...time.Duration) (*cstates.PreExecResult, error) {
	var buffer bytes.Buffer
	err := tx.Serialize(&buffer)
	if err != nil {
		return nil, fmt.Errorf("Serialize error:%s", err)
	}
	txData := hex.EncodeToString(buffer.Bytes())
	data, err := this.sendSyncWSRequest(WS_ACTION_SEND_TRANSACTION, map[string]interface{}{"Data": txData, "PreExec": "1"}, timeout...)
	if err != nil {
		return nil, fmt.Errorf("sendSyncWSRequest error:%s", err)
	}
	preResult := &cstates.PreExecResult{}
	err = json.Unmarshal(data, &preResult)
	if err != nil {
		return nil, fmt.Errorf("json.Unmarshal PreExecResult:%s error:%s", data, err)
	}
	return preResult, nil
}

func (this *WSClient) SignToTransaction(tx *types.Transaction, signer *account.Account) error {
	return sdkcom.SignToTransaction(tx, signer)
}

func (this *WSClient) GetActionCh() chan *WSAction {
	return this.actionCh
}

func (this *WSClient) WaitForGenerateBlock(timeout time.Duration, blockCount ...uint32) (bool, error) {
	f := func() (uint32, error) {
		return this.GetCurrentBlockHeight()
	}
	return utils.WaitForGenerateBlock(f, timeout, blockCount...)
}

func (this *WSClient) AsyncSendRawTransaction(tx *types.Transaction) (*WSRequest, error) {
	var buffer bytes.Buffer
	err := tx.Serialize(&buffer)
	if err != nil {
		return nil, fmt.Errorf("Serialize error:%s", err)
	}
	txData := hex.EncodeToString(buffer.Bytes())
	return this.sendAsyncWSRequest(WS_ACTION_SEND_TRANSACTION, map[string]interface{}{"Data": txData})
}

func (this *WSClient) AsyncPreInvokeContract(tx *types.Transaction) (*WSRequest, error) {
	var buffer bytes.Buffer
	err := tx.Serialize(&buffer)
	if err != nil {
		return nil, fmt.Errorf("Serialize error:%s", err)
	}
	txData := hex.EncodeToString(buffer.Bytes())
	return this.sendAsyncWSRequest(WS_ACTION_SEND_TRANSACTION, map[string]interface{}{"Data": txData, "PreExec": "1"})
}

func (this *WSClient) sendSyncWSRequest(action string, params map[string]interface{}, timeout ...time.Duration) ([]byte, error) {
	wsReq, err := this.sendAsyncWSRequest(action, params)
	if err != nil {
		return nil, err
	}

	var reqTimeout time.Duration
	if len(timeout) == 0 {
		reqTimeout = time.Duration(DEFAULT_REQ_TIMEOUT) * time.Second
	} else {
		reqTimeout = timeout[0]
	}
	reqTimer := time.NewTimer(reqTimeout)

	var wsRsp *WSResponse
	select {
	case wsRsp = <-wsReq.ResCh:
		reqTimer.Stop()
	case <-reqTimer.C:
		return nil, fmt.Errorf("sendSyncWSRequest action:%s id:%s timeout", action, wsReq.Id)
	}

	if wsRsp.Error != WS_ERROR_SUCCESS {
		return nil, fmt.Errorf("WSResponse error code:%d desc:%s result:%s", wsRsp.Error, wsRsp.Desc, wsRsp.Result)
	}
	return wsRsp.Result, nil
}

func (this *WSClient) sendAsyncWSRequest(action string, params map[string]interface{}) (*WSRequest, error) {
	reqParams := make(map[string]interface{})
	id := this.getNextQid()
	reqParams["Id"] = id
	reqParams["Version"] = WS_VERSION
	reqParams["Action"] = action
	for k, v := range params {
		reqParams[k] = v
	}
	data, err := json.Marshal(reqParams)
	if err != nil {
		return nil, fmt.Errorf("json.Marshal error:%s", err)
	}

	wsReq := &WSRequest{
		Id:     id,
		Params: reqParams,
		ResCh:  make(chan *WSResponse, 1),
	}
	this.addReq(wsReq)
	err = this.ws.Send(data)
	if err != nil {
		this.delReq(wsReq.Id)
		return nil, fmt.Errorf("send error:%s", err)
	}
	return wsReq, nil
}

func (this *WSClient) addReq(req *WSRequest) {
	this.lock.Lock()
	defer this.lock.Unlock()
	this.reqMap[req.Id] = req
}

func (this *WSClient) delReq(id string) {
	this.lock.Lock()
	defer this.lock.Unlock()
	delete(this.reqMap, id)
}

func (this *WSClient) getReq(id string) *WSRequest {
	this.lock.RLock()
	defer this.lock.RUnlock()
	return this.reqMap[id]
}

func (this *WSClient) getNextQid() string {
	return strconv.FormatUint(atomic.AddUint64(&this.qid, 1), 10)
}

func (this *WSClient) sendHeartbeat() {
	this.sendSyncWSRequest(WS_ACTION_HEARBEAT, nil)
	this.updateLastHeartbeatTime()
}

func (this *WSClient) Close() error {
	close(this.exitCh)
	return this.ws.Close()
}
