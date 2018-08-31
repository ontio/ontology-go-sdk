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
	"sync"
	"time"
)

type WSSubscribeStatus struct {
	ContractsFilter       []string
	SubscribeEvent        bool
	SubscribeJsonBlock    bool
	SubscribeRawBlock     bool
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
		defReqTimeout:     DEFAULT_REQ_TIMEOUT,
		heartbeatInterval: DEFAULT_WS_HEARTBEAT_INTERVAL,
		subStatus:         &WSSubscribeStatus{},
		ws:                utils.NewWebSocketClient(),
		reqMap:            make(map[string]*WSRequest),
		recvCh:            make(chan []byte, WS_RECV_CHAN_SIZE),
		actionCh:          make(chan *WSAction, WS_RECV_CHAN_SIZE),
		exitCh:            make(chan interface{}, 0),
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

func (this *WSClient) SetDefaultReqTimeout(timeout time.Duration) {
	this.defReqTimeout = timeout
}

func (this *WSClient) SetHeartbeatInterval(interval int) {
	this.heartbeatInterval = interval
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
			if int(time.Now().Sub(this.getLastHeartbeatTime()).Seconds()) >= this.heartbeatInterval {
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
		case WS_ACTION_HEARBEAT:
			return
		case WS_SUB_ACTION_RAW_BLOCK:
			this.onRawBlockAction(resp)
		case WS_SUB_ACTION_BLOCK_TX_HASH:
			this.onBlockTxHashesAction(resp)
		case WS_SUB_ACTION_NOTIFY:
			this.onSmartContractEventAction(resp)
		case WS_SUB_ACTION_LOG:
			this.onSmartContractEventLogAction(resp)
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
		Action: sdkcom.WS_SUBSCRIBE_ACTION_BLOCK,
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
		Action: sdkcom.WS_SUBSCRIBE_ACTION_BLOCK_TX_HASH,
		Result: blockTxHashes,
	}
}

func (this *WSClient) onSmartContractEventAction(resp *WSResponse) {
	event, err := utils.GetSmartContractEvent(resp.Result)
	if err != nil {
		this.ws.OnError(this.addr, fmt.Errorf("onSmartContractEventAction error:%s", err))
		return
	}
	this.actionCh <- &WSAction{
		Action: sdkcom.WS_SUBSCRIBE_ACTION_EVENT_NOTIFY,
		Result: event,
	}
}

func (this *WSClient) onSmartContractEventLogAction(resp *WSResponse) {
	log, err := utils.GetSmartContractEventLog(resp.Result)
	if err != nil {
		this.ws.OnError(this.addr, fmt.Errorf("onSmartContractEventLogAction error:%s", err))
		return
	}
	this.actionCh <- &WSAction{
		Action: sdkcom.WS_SUBSCRIBE_ACTION_EVENT_LOG,
		Result: log,
	}
}

func (this *WSClient) AddContractFilter(qid string, contractAddress string) error {
	if this.subStatus.HasContractFilter(contractAddress) {
		return nil
	}
	this.subStatus.AddContractFilter(contractAddress)
	_, err := this.sendSyncWSRequest(qid, WS_ACTION_SUBSCRIBE, map[string]interface{}{
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

func (this *WSClient) DelContractFilter(qid string, contractAddress string) error {
	if !this.subStatus.HasContractFilter(contractAddress) {
		return nil
	}
	this.subStatus.DelContractFilter(contractAddress)
	_, err := this.sendSyncWSRequest(qid, WS_ACTION_SUBSCRIBE, map[string]interface{}{
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

func (this *WSClient) SubscribeBlock(qid string) error {
	if this.subStatus.SubscribeRawBlock {
		return nil
	}
	_, err := this.sendSyncWSRequest(qid, WS_ACTION_SUBSCRIBE, map[string]interface{}{
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

func (this *WSClient) UnsubscribeBlock(qid string) error {
	if !this.subStatus.SubscribeRawBlock {
		return nil
	}
	_, err := this.sendSyncWSRequest(qid, WS_ACTION_SUBSCRIBE, map[string]interface{}{
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

func (this *WSClient) SubscribeEvent(qid string) error {
	if this.subStatus.SubscribeEvent {
		return nil
	}
	_, err := this.sendSyncWSRequest(qid, WS_ACTION_SUBSCRIBE, map[string]interface{}{
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

func (this *WSClient) UnsubscribeEvent(qid string) error {
	if !this.subStatus.SubscribeEvent {
		return nil
	}
	_, err := this.sendSyncWSRequest(qid, WS_ACTION_SUBSCRIBE, map[string]interface{}{
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

func (this *WSClient) SubscribeTxHash(qid string) error {
	if this.subStatus.SubscribeBlockTxHashes {
		return nil
	}
	_, err := this.sendSyncWSRequest(qid, WS_ACTION_SUBSCRIBE, map[string]interface{}{
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

func (this *WSClient) UnsubscribeTxHash(qid string) error {
	if !this.subStatus.SubscribeBlockTxHashes {
		return nil
	}
	_, err := this.sendSyncWSRequest(qid, WS_ACTION_SUBSCRIBE, map[string]interface{}{
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
	params["PreExec"] = "1"
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

func (this *WSClient) getGenerateBlockTime(qid string) ([]byte, error) {
	return this.sendSyncWSRequest(qid, WS_ACTION_GET_GENERATE_BLOCK_TIME, nil)
}

func (this *WSClient) getActionCh() chan *WSAction {
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
	err = this.ws.Send(data)
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
	this.updateLastHeartbeatTime()
}

func (this *WSClient) Close() error {
	close(this.exitCh)
	return this.ws.Close()
}
