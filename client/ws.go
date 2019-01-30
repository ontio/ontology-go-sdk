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
package client

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	sdkcom "github.com/ontio/ontology-go-sdk/common"
	"github.com/ontio/ontology-go-sdk/utils"
	"github.com/ontio/ontology/core/types"
	"math/rand"
	"strconv"
	"sync"
	"time"
)

type WSSubscribeStatus struct {
	ContractsFilter        []string
	SubscribeEvent         bool
	SubscribeJsonBlock     bool
	SubscribeRawBlock      bool
	SubscribeBlockTxHashes bool
}

func (this *WSSubscribeStatus) GetContractFilter() []string {
	contracts := make([]string, len(this.ContractsFilter))
	copy(contracts, this.ContractsFilter)
	return contracts
}

func (this *WSSubscribeStatus) HasContractFilter(contractAddress string) bool {
	for _, address := range this.ContractsFilter {
		if address == contractAddress {
			return true
		}
	}
	return false
}

func (this *WSSubscribeStatus) AddContractFilter(contractAddress string) {
	if this.ContractsFilter == nil {
		this.ContractsFilter = make([]string, 0)
	}
	if this.HasContractFilter(contractAddress) {
		return
	}
	this.ContractsFilter = append(this.ContractsFilter, contractAddress)
}

func (this *WSSubscribeStatus) DelContractFilter(contractAddress string) {
	size := len(this.ContractsFilter)
	if size == 0 {
		return
	}
	for index, address := range this.ContractsFilter {
		if address == contractAddress {
			if index == size-1 {
				this.ContractsFilter = this.ContractsFilter[:index]
			} else {
				this.ContractsFilter = append(this.ContractsFilter[:index], this.ContractsFilter[index+1:]...)
			}
			break
		}
	}
}

type WSClient struct {
	addr              string
	defReqTimeout     time.Duration
	heartbeatInterval int
	heartbeatTimeout  int
	subStatus         *WSSubscribeStatus
	ws                *utils.WebSocketClient
	reqMap            map[string]*WSRequest
	recvCh            chan []byte
	actionCh          chan *WSAction
	exitCh            chan interface{}
	lastHeartbeatTime time.Time
	lastRecvTime      time.Time
	onConnect         func(address string)
	onClose           func(address string)
	onError           func(address string, err error)
	lock              sync.RWMutex
}

func NewWSClient() *WSClient {
	wsClient := &WSClient{
		defReqTimeout:     DEFAULT_REQ_TIMEOUT,
		heartbeatInterval: DEFAULT_WS_HEARTBEAT_INTERVAL,
		heartbeatTimeout:  DEFAULT_WS_HEARTBEAT_TIMEOUT,
		subStatus:         &WSSubscribeStatus{},
		reqMap:            make(map[string]*WSRequest),
		recvCh:            make(chan []byte, WS_RECV_CHAN_SIZE),
		actionCh:          make(chan *WSAction, WS_RECV_CHAN_SIZE),
		lastHeartbeatTime: time.Now(),
		lastRecvTime:      time.Now(),
		exitCh:            make(chan interface{}, 0),
	}
	go wsClient.start()
	return wsClient
}

func (this *WSClient) Connect(address string) error {
	if this.getWsClient() != nil {
		return fmt.Errorf("address:%s has already connect", this.addr)
	}
	if address == "" {
		return fmt.Errorf("address cannot empty")
	}
	this.addr = address
	ws := utils.NewWebSocketClient()
	ws.OnMessage = this.onMessage
	ws.OnError = this.GetOnError()
	ws.OnConnect = this.GetOnConnect()
	ws.OnClose = this.GetOnClose()

	err := ws.Connect(address)
	if err != nil {
		return err
	}
	this.setWsClient(ws)
	return nil
}

func (this *WSClient) GetDefaultReqTimeout() time.Duration {
	this.lock.RLock()
	defer this.lock.RUnlock()
	return this.defReqTimeout
}

func (this *WSClient) SetDefaultReqTimeout(timeout time.Duration) {
	this.lock.Lock()
	defer this.lock.Unlock()
	this.defReqTimeout = timeout
}

func (this *WSClient) GetHeartbeatInterval() int {
	this.lock.RLock()
	defer this.lock.RUnlock()
	return this.heartbeatInterval
}

func (this *WSClient) SetHeartbeatInterval(interval int) {
	this.lock.Lock()
	defer this.lock.Unlock()
	this.heartbeatInterval = interval
}

func (this *WSClient) GetHeartbeatTimeout() int {
	this.lock.RLock()
	defer this.lock.RUnlock()
	return this.heartbeatTimeout
}

func (this *WSClient) SetHeartbeatTimeout(timeout int) {
	this.lock.Lock()
	defer this.lock.Unlock()
	this.heartbeatTimeout = timeout
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

func (this *WSClient) updateLastRecvTime() {
	this.lock.Lock()
	defer this.lock.Unlock()
	this.lastRecvTime = time.Now()
}

func (this *WSClient) getLastRecvTime() time.Time {
	this.lock.RLock()
	defer this.lock.RUnlock()
	return this.lastRecvTime
}

func (this *WSClient) GetOnConnect() func(address string) {
	this.lock.RLock()
	defer this.lock.RUnlock()
	if this.onConnect != nil {
		return this.onConnect
	}
	return this.onDefConnect
}

func (this *WSClient) SetOnConnect(f func(address string)) {
	this.lock.Lock()
	defer this.lock.Unlock()
	this.onConnect = f
	ws := this.getWsClient()
	if ws != nil {
		ws.OnConnect = f
	}
}

func (this *WSClient) GetOnClose() func(address string) {
	this.lock.RLock()
	defer this.lock.RUnlock()
	if this.onClose != nil {
		return this.onClose
	}
	return this.onDefClose
}

func (this *WSClient) SetOnClose(f func(address string)) {
	this.lock.Lock()
	defer this.lock.Unlock()
	this.onClose = f
	ws := this.getWsClient()
	if ws != nil {
		ws.OnClose = f
	}
}

func (this *WSClient) GetOnError() func(address string, er error) {
	this.lock.RLock()
	defer this.lock.RUnlock()
	if this.onError != nil {
		return this.onError
	}
	return this.onDefError
}

func (this *WSClient) SetOnError(f func(address string, err error)) {
	this.lock.Lock()
	defer this.lock.Unlock()
	this.onError = f
	ws := this.getWsClient()
	if ws != nil {
		ws.OnError = f
	}
}

func (this *WSClient) onMessage(data []byte) {
	this.updateLastHeartbeatTime()
	this.updateLastRecvTime()
	select {
	case this.recvCh <- data:
	case <-this.exitCh:
		return
	}
}

func (this *WSClient) onDefError(address string, err error) {
	fmt.Printf("WSClient OnError address:%s error:%s\n", address, err)
}

func (this *WSClient) onDefConnect(address string) {
	fmt.Printf("WSClient OnConnect address:%s connect success\n", address)
}

func (this *WSClient) onDefClose(address string) {
	fmt.Printf("WSClient OnClose address:%s close success\n", address)
}

func (this *WSClient) start() {
	heartbeatTimer := time.NewTicker(time.Second)
	defer heartbeatTimer.Stop()
	for {
		select {
		case <-this.exitCh:
			return
		case data := <-this.recvCh:
			wsResp := &WSResponse{}
			err := json.Unmarshal(data, wsResp)
			if err != nil {
				this.GetOnError()(this.addr, fmt.Errorf("json.Unmarshal WSResponse error:%s", err))
			} else {
				go this.onAction(wsResp)
			}
		case <-heartbeatTimer.C:
			now := time.Now()
			if int(now.Sub(this.getLastRecvTime()).Seconds()) >= this.GetHeartbeatTimeout() {
				go this.reconnect()
				this.updateLastRecvTime()
			} else if int(now.Sub(this.getLastHeartbeatTime()).Seconds()) >= this.GetHeartbeatInterval() {
				go this.sendHeartbeat()
				this.updateLastHeartbeatTime()
			}
		}
	}
}

func (this *WSClient) reconnect() {
	ws := this.getWsClient()
	if ws != nil {
		this.setWsClient(nil)
		err := ws.Close()
		if err != nil {
			this.GetOnError()(this.addr, fmt.Errorf("close error:%s", err))
		}
		ws.OnMessage = nil
	}
	err := this.Connect(this.addr)
	if err != nil {
		this.GetOnError()(this.addr, fmt.Errorf("connect error:%s", err))
		return
	}
	err = this.reSubscribe()
	if err != nil {
		this.GetOnError()(this.addr, fmt.Errorf("reSubscribe:%v error:%s", this.subStatus, err))
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
			this.onSmartContractEventAction(resp)
		case WS_SUB_ACTION_LOG:
			this.onSmartContractEventLogAction(resp)
		default:
			this.GetOnError()(this.addr, fmt.Errorf("unknown subscribe action:%s", resp.Action))
		}
		return
	}
	req := this.getReq(resp.Id)
	if req == nil {
		return
	}
	select {
	case req.ResCh <- resp:
	case <-this.exitCh:
		return
	}
	this.delReq(resp.Id)
}

func (this *WSClient) onRawBlockAction(resp *WSResponse) {
	block, err := utils.GetBlock(resp.Result)
	if err != nil {
		this.GetOnError()(this.addr, fmt.Errorf("onRawBlockAction error:%s", err))
		return
	}
	select {
	case this.actionCh <- &WSAction{
		Action: sdkcom.WS_SUBSCRIBE_ACTION_BLOCK,
		Result: block,
	}:
	case <-this.exitCh:
		return
	}
}

func (this *WSClient) onBlockTxHashesAction(resp *WSResponse) {
	blockTxHashes, err := utils.GetBlockTxHashes(resp.Result)
	if err != nil {
		this.GetOnError()(this.addr, fmt.Errorf("onBlockTxHashesAction error:%s", err))
		return
	}
	select {
	case this.actionCh <- &WSAction{
		Action: sdkcom.WS_SUBSCRIBE_ACTION_BLOCK_TX_HASH,
		Result: blockTxHashes,
	}:
	case <-this.exitCh:
		return
	}
}

func (this *WSClient) onSmartContractEventAction(resp *WSResponse) {
	event, err := utils.GetSmartContractEvent(resp.Result)
	if err != nil {
		this.GetOnError()(this.addr, fmt.Errorf("onSmartContractEventAction error:%s", err))
		return
	}
	select {
	case this.actionCh <- &WSAction{
		Action: sdkcom.WS_SUBSCRIBE_ACTION_EVENT_NOTIFY,
		Result: event,
	}:
	case <-this.exitCh:
		return
	}
}

func (this *WSClient) onSmartContractEventLogAction(resp *WSResponse) {
	log, err := utils.GetSmartContractEventLog(resp.Result)
	if err != nil {
		this.GetOnError()(this.addr, fmt.Errorf("onSmartContractEventLogAction error:%s", err))
		return
	}
	select {
	case this.actionCh <- &WSAction{
		Action: sdkcom.WS_SUBSCRIBE_ACTION_EVENT_LOG,
		Result: log,
	}:
	case <-this.exitCh:
		return
	}
}

func (this *WSClient) AddContractFilter(contractAddress string) error {
	if this.subStatus.HasContractFilter(contractAddress) {
		return nil
	}
	this.subStatus.AddContractFilter(contractAddress)
	_, err := this.sendSyncWSRequest("", WS_ACTION_SUBSCRIBE, map[string]interface{}{
		WS_SUB_CONTRACT_FILTER: this.subStatus.GetContractFilter(),
		WS_SUB_EVENT:           this.subStatus.SubscribeEvent,
		WS_SUB_JSON_BLOCK:      this.subStatus.SubscribeJsonBlock,
		WS_SUB_RAW_BLOCK:       this.subStatus.SubscribeRawBlock,
		WS_SUB_BLOCK_TX_HASH:   this.subStatus.SubscribeBlockTxHashes,
	})
	if err != nil {
		this.subStatus.DelContractFilter(contractAddress)
		return err
	}
	return nil
}

func (this *WSClient) DelContractFilter(contractAddress string) error {
	if !this.subStatus.HasContractFilter(contractAddress) {
		return nil
	}
	this.subStatus.DelContractFilter(contractAddress)
	_, err := this.sendSyncWSRequest("", WS_ACTION_SUBSCRIBE, map[string]interface{}{
		WS_SUB_CONTRACT_FILTER: this.subStatus.GetContractFilter(),
		WS_SUB_EVENT:           this.subStatus.SubscribeEvent,
		WS_SUB_JSON_BLOCK:      this.subStatus.SubscribeJsonBlock,
		WS_SUB_RAW_BLOCK:       this.subStatus.SubscribeRawBlock,
		WS_SUB_BLOCK_TX_HASH:   this.subStatus.SubscribeBlockTxHashes,
	})
	if err != nil {
		this.subStatus.AddContractFilter(contractAddress)
		return err
	}
	return nil
}

func (this *WSClient) SubscribeBlock() error {
	if this.subStatus.SubscribeRawBlock {
		return nil
	}
	_, err := this.sendSyncWSRequest("", WS_ACTION_SUBSCRIBE, map[string]interface{}{
		WS_SUB_CONTRACT_FILTER: this.subStatus.GetContractFilter(),
		WS_SUB_EVENT:           this.subStatus.SubscribeEvent,
		WS_SUB_JSON_BLOCK:      this.subStatus.SubscribeJsonBlock,
		WS_SUB_RAW_BLOCK:       true,
		WS_SUB_BLOCK_TX_HASH:   this.subStatus.SubscribeBlockTxHashes,
	})
	if err != nil {
		return err
	}
	this.subStatus.SubscribeRawBlock = true
	return nil
}

func (this *WSClient) UnsubscribeBlock() error {
	if !this.subStatus.SubscribeRawBlock {
		return nil
	}
	_, err := this.sendSyncWSRequest("", WS_ACTION_SUBSCRIBE, map[string]interface{}{
		WS_SUB_CONTRACT_FILTER: this.subStatus.GetContractFilter(),
		WS_SUB_EVENT:           this.subStatus.SubscribeEvent,
		WS_SUB_JSON_BLOCK:      this.subStatus.SubscribeJsonBlock,
		WS_SUB_RAW_BLOCK:       false,
		WS_SUB_BLOCK_TX_HASH:   this.subStatus.SubscribeBlockTxHashes,
	})
	if err != nil {
		return err
	}
	this.subStatus.SubscribeRawBlock = false
	return nil
}

func (this *WSClient) SubscribeEvent() error {
	if this.subStatus.SubscribeEvent {
		return nil
	}
	_, err := this.sendSyncWSRequest("", WS_ACTION_SUBSCRIBE, map[string]interface{}{
		WS_SUB_CONTRACT_FILTER: this.subStatus.GetContractFilter(),
		WS_SUB_EVENT:           true,
		WS_SUB_JSON_BLOCK:      this.subStatus.SubscribeJsonBlock,
		WS_SUB_RAW_BLOCK:       this.subStatus.SubscribeRawBlock,
		WS_SUB_BLOCK_TX_HASH:   this.subStatus.SubscribeBlockTxHashes,
	})
	if err != nil {
		return err
	}
	this.subStatus.SubscribeEvent = true
	return nil
}

func (this *WSClient) UnsubscribeEvent() error {
	if !this.subStatus.SubscribeEvent {
		return nil
	}
	_, err := this.sendSyncWSRequest("", WS_ACTION_SUBSCRIBE, map[string]interface{}{
		WS_SUB_CONTRACT_FILTER: this.subStatus.GetContractFilter(),
		WS_SUB_EVENT:           false,
		WS_SUB_JSON_BLOCK:      this.subStatus.SubscribeJsonBlock,
		WS_SUB_RAW_BLOCK:       this.subStatus.SubscribeRawBlock,
		WS_SUB_BLOCK_TX_HASH:   this.subStatus.SubscribeBlockTxHashes,
	})
	if err != nil {
		return err
	}
	this.subStatus.SubscribeEvent = false
	return nil
}

func (this *WSClient) SubscribeTxHash() error {
	if this.subStatus.SubscribeBlockTxHashes {
		return nil
	}
	_, err := this.sendSyncWSRequest("", WS_ACTION_SUBSCRIBE, map[string]interface{}{
		WS_SUB_CONTRACT_FILTER: this.subStatus.GetContractFilter(),
		WS_SUB_EVENT:           this.subStatus.SubscribeEvent,
		WS_SUB_JSON_BLOCK:      this.subStatus.SubscribeJsonBlock,
		WS_SUB_RAW_BLOCK:       this.subStatus.SubscribeRawBlock,
		WS_SUB_BLOCK_TX_HASH:   true,
	})
	if err != nil {
		return err
	}
	this.subStatus.SubscribeBlockTxHashes = true
	return nil
}

func (this *WSClient) UnsubscribeTxHash() error {
	if !this.subStatus.SubscribeBlockTxHashes {
		return nil
	}
	_, err := this.sendSyncWSRequest("", WS_ACTION_SUBSCRIBE, map[string]interface{}{
		WS_SUB_CONTRACT_FILTER: this.subStatus.GetContractFilter(),
		WS_SUB_EVENT:           this.subStatus.SubscribeEvent,
		WS_SUB_JSON_BLOCK:      this.subStatus.SubscribeJsonBlock,
		WS_SUB_RAW_BLOCK:       this.subStatus.SubscribeRawBlock,
		WS_SUB_BLOCK_TX_HASH:   false,
	})
	if err != nil {
		return err
	}
	this.subStatus.SubscribeBlockTxHashes = false
	return nil
}

func (this *WSClient) reSubscribe() error {
	_, err := this.sendSyncWSRequest("", WS_ACTION_SUBSCRIBE, map[string]interface{}{
		WS_SUB_CONTRACT_FILTER: this.subStatus.GetContractFilter(),
		WS_SUB_EVENT:           this.subStatus.SubscribeEvent,
		WS_SUB_JSON_BLOCK:      this.subStatus.SubscribeJsonBlock,
		WS_SUB_RAW_BLOCK:       this.subStatus.SubscribeRawBlock,
		WS_SUB_BLOCK_TX_HASH:   this.subStatus.SubscribeBlockTxHashes,
	})
	return err
}

func (this *WSClient) getVersion(qid string) ([]byte, error) {
	return this.sendSyncWSRequest(qid, WS_ACTION_GET_VERSION, nil)
}

func (this *WSClient) getNetworkId(qid string) ([]byte, error) {
	return this.sendSyncWSRequest(qid, WS_ACTION_GET_NETWORK_ID, nil)
}

func (this *WSClient) getBlockByHash(qid, hash string) ([]byte, error) {
	return this.sendSyncWSRequest(qid, WS_ACTION_GET_BLOCK_BY_HASH, map[string]interface{}{"Raw": "1", "Hash": hash})
}

func (this *WSClient) getBlockByHeight(qid string, height uint32) ([]byte, error) {
	return this.sendSyncWSRequest(qid, WS_ACTION_GET_BLOCK_BY_HEIGHT, map[string]interface{}{"Raw": "1", "Height": height})
}

func (this *WSClient) getBlockInfoByHeight(qid string, height uint32) ([]byte, error) {
	return this.sendSyncWSRequest(qid, WS_ACTION_GET_BLOCK_BY_HEIGHT, map[string]interface{}{"Raw": "0", "Height": height})
}

func (this *WSClient) getBlockHash(qid string, height uint32) ([]byte, error) {
	return this.sendSyncWSRequest(qid, WS_ACTION_GET_BLOCK_HASH, map[string]interface{}{"Height": height})
}

func (this *WSClient) getRawTransaction(qid, txHash string) ([]byte, error) {
	return this.sendSyncWSRequest(qid, WS_ACTION_GET_TRANSACTION, map[string]interface{}{"Raw": "1", "Hash": txHash})
}

func (this *WSClient) sendRawTransaction(qid string, tx *types.Transaction, isPreExec bool) ([]byte, error) {
	var buffer bytes.Buffer
	err := tx.Serialize(&buffer)
	if err != nil {
		return nil, fmt.Errorf("serialize error:%s", err)
	}
	txData := hex.EncodeToString(buffer.Bytes())
	params := map[string]interface{}{"Data": txData}
	if isPreExec {
		params["PreExec"] = "1"
	}
	return this.sendSyncWSRequest(qid, WS_ACTION_SEND_TRANSACTION, params)
}

func (this *WSClient) getMemPoolTxState(qid, txHash string) ([]byte, error) {
	return this.sendSyncWSRequest(qid, WS_ACTION_GET_MEM_POOL_TX_STATE, map[string]interface{}{"Hash": txHash})
}

func (this *WSClient) getMemPoolTxCount(qid string) ([]byte, error) {
	return this.sendSyncWSRequest(qid, WS_ACTION_GET_MEM_POOL_TX_COUNT, nil)
}

func (this *WSClient) getCurrentBlockHeight(qid string) ([]byte, error) {
	return this.sendSyncWSRequest(qid, WS_ACTION_GET_BLOCK_HEIGHT, nil)
}

func (this *WSClient) getCurrentBlockHash(qid string) ([]byte, error) {
	data, err := this.getCurrentBlockHeight(qid)
	if err != nil {
		return nil, err
	}
	height, err := utils.GetUint32(data)
	if err != nil {
		return nil, err
	}
	return this.getBlockHash(qid, height)
}

func (this *WSClient) getBlockHeightByTxHash(qid, txHash string) ([]byte, error) {
	return this.sendSyncWSRequest(qid, WS_ACTION_GET_BLOCK_HEIGHT_BY_TX_HASH, map[string]interface{}{"Hash": txHash})
}

func (this *WSClient) getBlockTxHashesByHeight(qid string, height uint32) ([]byte, error) {
	return this.sendSyncWSRequest(qid, WS_ACTION_GET_BLOCK_TX_HASH_BY_HEIGHT, map[string]interface{}{"Height": height})
}

func (this *WSClient) getStorage(qid, contractAddress string, key []byte) ([]byte, error) {
	return this.sendSyncWSRequest(qid, WS_ACTION_GET_STORAGE, map[string]interface{}{"Hash": contractAddress, "Key": hex.EncodeToString(key)})
}

func (this *WSClient) getShardStorage(shardID uint64, qid, contractAddress string, key []byte) ([]byte, error) {
	return this.sendSyncWSRequest(qid, WS_ACTION_GET_SHARD_STORAGE,
		map[string]interface{}{
			"ShardID": shardID,
			"Hash":    contractAddress,
			"Key":     hex.EncodeToString(key),
		},
	)
}

func (this *WSClient) getSmartContract(qid, contractAddress string) ([]byte, error) {
	return this.sendSyncWSRequest(qid, WS_ACTION_GET_CONTRACT, map[string]interface{}{"Hash": contractAddress, "Raw": "1"})
}

func (this *WSClient) getMerkleProof(qid, txHash string) ([]byte, error) {
	return this.sendSyncWSRequest(qid, WS_ACTION_GET_MERKLE_PROOF, map[string]interface{}{"Hash": txHash})
}

func (this *WSClient) getSmartContractEvent(qid, txHash string) ([]byte, error) {
	return this.sendSyncWSRequest(qid, WS_ACTION_GET_SMARTCONTRACT_BY_HASH, map[string]interface{}{"Hash": txHash})
}

func (this *WSClient) getSmartContractEventByBlock(qid string, blockHeight uint32) ([]byte, error) {
	return this.sendSyncWSRequest(qid, WS_ACTION_GET_SMARTCONTRACT_BY_HEIGHT, map[string]interface{}{"Height": blockHeight})
}

func (this *WSClient) GetActionCh() chan *WSAction {
	return this.actionCh
}

func (this *WSClient) sendAsyncRawTransaction(qid string, tx *types.Transaction, isPreExec bool) (*WSRequest, error) {
	var buffer bytes.Buffer
	err := tx.Serialize(&buffer)
	if err != nil {
		return nil, fmt.Errorf("serialize error:%s", err)
	}
	txData := hex.EncodeToString(buffer.Bytes())
	params := map[string]interface{}{"Data": txData}
	if isPreExec {
		params["PreExec"] = "1"
	}
	return this.sendAsyncWSRequest(qid, WS_ACTION_SEND_TRANSACTION, params)
}

func (this *WSClient) sendSyncWSRequest(qid, action string, params map[string]interface{}) ([]byte, error) {
	if qid == "" {
		qid = strconv.Itoa(int(rand.Int31()))
	}
	wsReq, err := this.sendAsyncWSRequest(qid, action, params)
	if err != nil {
		return nil, err
	}
	reqTimer := time.NewTimer(this.defReqTimeout)
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

func (this *WSClient) sendAsyncWSRequest(qid, action string, params map[string]interface{}) (*WSRequest, error) {
	reqParams := make(map[string]interface{})
	reqParams["Id"] = qid
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
		Id:     qid,
		Params: reqParams,
		ResCh:  make(chan *WSResponse, 1),
	}
	this.addReq(wsReq)
	ws := this.getWsClient()
	if ws == nil {
		return nil, fmt.Errorf("ws client is nil")
	}
	err = ws.Send(data)
	if err != nil {
		this.delReq(wsReq.Id)
		return nil, fmt.Errorf("send error:%s", err)
	}
	return wsReq, nil
}

func (this *WSClient) addReq(req *WSRequest) {
	if req.Id == "" {
		return
	}
	this.lock.Lock()
	defer this.lock.Unlock()
	this.reqMap[req.Id] = req
}

func (this *WSClient) delReq(id string) {
	if id == "" {
		return
	}
	this.lock.Lock()
	defer this.lock.Unlock()
	delete(this.reqMap, id)
}

func (this *WSClient) getReq(id string) *WSRequest {
	if id == "" {
		return nil
	}
	this.lock.RLock()
	defer this.lock.RUnlock()
	return this.reqMap[id]
}

func (this *WSClient) sendHeartbeat() {
	this.sendSyncWSRequest("", WS_ACTION_HEARBEAT, nil)
}

func (this *WSClient) setWsClient(ws *utils.WebSocketClient) {
	this.lock.Lock()
	defer this.lock.Unlock()
	this.ws = ws
}

func (this *WSClient) getWsClient() *utils.WebSocketClient {
	this.lock.RLock()
	defer this.lock.RUnlock()
	return this.ws
}

func (this *WSClient) Close() error {
	close(this.exitCh)
	ws := this.getWsClient()
	if ws != nil {
		return ws.Close()
	}
	return nil
}
