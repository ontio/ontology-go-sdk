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
	"github.com/ontio/ontology-go-sdk/utils"
	"github.com/ontio/ontology/core/types"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"
)

//RpcClient for ontology rpc api
type RestClient struct {
	addr       string
	httpClient *http.Client
}

//NewRpcClient return RpcClient instance
func NewRestClient() *RestClient {
	return &RestClient{
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

//SetAddress set rest server address. Simple http://localhost:20334
func (this *RestClient) SetAddress(addr string) *RestClient {
	this.addr = addr
	return this
}

//SetHttpClient set rest client to RestClient. In most cases SetHttpClient is not necessary
func (this *RestClient) SetHttpClient(httpClient *http.Client) *RestClient {
	this.httpClient = httpClient
	return this
}

func (this *RestClient) getVersion(qid string) ([]byte, error) {
	reqPath := GET_VERSION
	return this.sendRestGetRequest(reqPath)
}

func (this *RestClient) getNetworkId(qid string) ([]byte, error) {
	reqPath := GET_NETWORK_ID
	return this.sendRestGetRequest(reqPath)
}

func (this *RestClient) getBlockByHash(qid, hash string) ([]byte, error) {
	reqPath := GET_BLK_BY_HASH + hash
	reqValues := &url.Values{}
	reqValues.Add("raw", "1")
	return this.sendRestGetRequest(reqPath, reqValues)
}

func (this *RestClient) getBlockByHeight(qid string, height uint32) ([]byte, error) {
	reqPath := fmt.Sprintf("%s%d", GET_BLK_BY_HEIGHT, height)
	reqValues := &url.Values{}
	reqValues.Add("raw", "1")
	return this.sendRestGetRequest(reqPath, reqValues)
}

func (this *RestClient) getBlockInfoByHeight(qid string, height uint32) ([]byte, error) {
	reqPath := fmt.Sprintf("%s%d", GET_BLK_BY_HEIGHT, height)
	reqValues := &url.Values{}
	reqValues.Add("raw", "0")
	return this.sendRestGetRequest(reqPath, reqValues)
}

func (this *RestClient) getCurrentBlockHeight(qid string) ([]byte, error) {
	reqPath := GET_BLK_HEIGHT
	return this.sendRestGetRequest(reqPath)
}

func (this *RestClient) getCurrentBlockHash(qid string) ([]byte, error) {
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

func (this *RestClient) getBlockHash(qid string, height uint32) ([]byte, error) {
	reqPath := fmt.Sprintf("%s%d", GET_BLK_HASH, height)
	return this.sendRestGetRequest(reqPath)
}

//GetRawTransaction return transaction by transaction hash in hex string code
func (this *RestClient) getRawTransaction(qid, txHash string) ([]byte, error) {
	reqPath := GET_TX + txHash
	reqValues := &url.Values{}
	reqValues.Add("raw", "1")
	return this.sendRestGetRequest(reqPath, reqValues)
}

func (this *RestClient) getStorage(qid, contractAddress string, key []byte) ([]byte, error) {
	reqPath := GET_STORAGE + contractAddress + "/" + hex.EncodeToString(key)
	return this.sendRestGetRequest(reqPath)
}

func (this *RestClient) getShardStorage(shardID uint64, qid, contractAddress string, key []byte) ([]byte, error) {
	reqPath := GET_SHARD_STORAGE + "/" + fmt.Sprintf("%d", shardID) + "/" + contractAddress + "/" + hex.EncodeToString(key)
	return this.sendRestGetRequest(reqPath)
}

//GetSmartContractEvent return smart contract event execute by invoke transaction by hex string code
func (this *RestClient) getSmartContractEvent(qid, txHash string) ([]byte, error) {
	reqPath := GET_SMTCOCE_EVTS + txHash
	return this.sendRestGetRequest(reqPath)
}

func (this *RestClient) getSmartContractEventByBlock(qid string, blockHeight uint32) ([]byte, error) {
	reqPath := fmt.Sprintf("%s%d", GET_SMTCOCE_EVT_TXS, blockHeight)
	return this.sendRestGetRequest(reqPath)
}

func (this *RestClient) getSmartContract(qid, contractAddress string) ([]byte, error) {
	reqPath := GET_CONTRACT_STATE + contractAddress
	reqValues := &url.Values{}
	reqValues.Add("raw", "1")
	return this.sendRestGetRequest(reqPath, reqValues)
}

func (this RestClient) getMerkleProof(qid, txHash string) ([]byte, error) {
	reqPath := GET_MERKLE_PROOF + txHash
	return this.sendRestGetRequest(reqPath)
}

func (this *RestClient) getMemPoolTxState(qid, txHash string) ([]byte, error) {
	reqPath := GET_MEMPOOL_TXSTATE + txHash
	return this.sendRestGetRequest(reqPath)
}

func (this *RestClient) getMemPoolTxCount(qid string) ([]byte, error) {
	reqPath := GET_MEMPOOL_TXCOUNT
	return this.sendRestGetRequest(reqPath)
}

func (this *RestClient) getBlockHeightByTxHash(qid, txHash string) ([]byte, error) {
	reqPath := GET_BLK_HGT_BY_TXHASH + txHash
	return this.sendRestGetRequest(reqPath)
}

func (this *RestClient) getBlockTxHashesByHeight(qid string, height uint32) ([]byte, error) {
	reqPath := fmt.Sprintf("%s%d", GET_BLK_TXS_BY_HEIGHT, height)
	return this.sendRestGetRequest(reqPath)
}

func (this *RestClient) sendRawTransaction(qid string, tx *types.Transaction, isPreExec bool) ([]byte, error) {
	reqPath := POST_RAW_TX
	var buffer bytes.Buffer
	err := tx.Serialize(&buffer)
	if err != nil {
		return nil, fmt.Errorf("Serialize error:%s", err)
	}
	var reqValues *url.Values
	if isPreExec {
		reqValues = &url.Values{}
		reqValues.Add("preExec", "1")
	}
	return this.sendRestPostRequest(buffer.Bytes(), reqPath, reqValues)
}

func (this *RestClient) getAddress() (string, error) {
	if this.addr == "" {
		return "", fmt.Errorf("cannot get address, please add adrress first")
	}
	return this.addr, nil
}

func (this *RestClient) getRequestUrl(reqPath string, values ...*url.Values) (string, error) {
	addr, err := this.getAddress()
	if err != nil {
		return "", err
	}
	if !strings.HasPrefix(addr, "http") {
		addr = "http://" + addr
	}
	reqUrl, err := new(url.URL).Parse(addr)
	if err != nil {
		return "", fmt.Errorf("Parse address:%s error:%s", addr, err)
	}
	reqUrl.Path = reqPath
	if len(values) > 0 && values[0] != nil {
		reqUrl.RawQuery = values[0].Encode()
	}
	return reqUrl.String(), nil
}

func (this *RestClient) sendRestGetRequest(reqPath string, values ...*url.Values) ([]byte, error) {
	reqUrl, err := this.getRequestUrl(reqPath, values...)
	if err != nil {
		return nil, err
	}
	resp, err := this.httpClient.Get(reqUrl)
	if err != nil {
		return nil, fmt.Errorf("send http get request error:%s", err)
	}
	defer resp.Body.Close()
	return this.dealRestResponse(resp.Body)
}

func (this *RestClient) sendRestPostRequest(data []byte, reqPath string, values ...*url.Values) ([]byte, error) {
	reqUrl, err := this.getRequestUrl(reqPath, values...)
	if err != nil {
		return nil, err
	}
	restReq := &RestfulReq{
		Action:  ACTION_SEND_RAW_TRANSACTION,
		Version: REST_VERSION,
		Data:    hex.EncodeToString(data),
	}
	reqData, err := json.Marshal(restReq)
	if err != nil {
		return nil, fmt.Errorf("json.Marshal error:%s", err)
	}
	resp, err := this.httpClient.Post(reqUrl, "application/json", bytes.NewReader(reqData))
	if err != nil {
		return nil, fmt.Errorf("send http post request error:%s", err)
	}
	defer resp.Body.Close()
	return this.dealRestResponse(resp.Body)
}

func (this *RestClient) dealRestResponse(body io.Reader) ([]byte, error) {
	data, err := ioutil.ReadAll(body)
	if err != nil {
		return nil, fmt.Errorf("read http body error:%s", err)
	}
	restRsp := &RestfulResp{}
	err = json.Unmarshal(data, restRsp)
	if err != nil {
		return nil, fmt.Errorf("json.Unmarshal RestfulResp:%s error:%s", body, err)
	}
	if restRsp.Error != 0 {
		return nil, fmt.Errorf("sendRestRequest error code:%d desc:%s result:%s", restRsp.Error, restRsp.Desc, restRsp.Result)
	}
	return restRsp.Result, nil
}
