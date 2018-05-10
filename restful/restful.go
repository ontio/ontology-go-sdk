package restful

import (
	"github.com/ontio/ontology-go-sdk/utils"
	"net/http"
	"time"
	"fmt"
	"io/ioutil"
	"encoding/json"
	"strconv"
	"github.com/ontio/ontology/common"
	"github.com/ontio/ontology/core/types"
	sdkcom "github.com/ontio/ontology-go-sdk/common"
	"encoding/hex"
	"math/big"
	"github.com/ontio/ontology/account"
	"bytes"
	"strings"
	"github.com/ontio/ontology/core/genesis"
	vmtypes "github.com/ontio/ontology/smartcontract/types"
	"github.com/ontio/ontology/core/payload"
	"github.com/ontio/ontology-crypto/keypair"
	sig "github.com/ontio/ontology-crypto/signature"
	"github.com/ontio/ontology/smartcontract/service/native/ont"
	cstates "github.com/ontio/ontology/smartcontract/states"
)

type RestfulClient struct{
	cryptScheme string
	qid         uint64
	addr        string
	httpClient  *http.Client

}

func NewRestfulClient(cryptScheme string) *RestfulClient {

	return &RestfulClient{
		cryptScheme:cryptScheme,
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

func (this *RestfulClient) SetCryptScheme(cryptScheme string) {
	this.cryptScheme = cryptScheme
}

func (this *RestfulClient) SetAddress(addr string) *RestfulClient {
	this.addr = addr
	return this
}

func (this *RestfulClient) SetHttpClient(httpClient *http.Client) *RestfulClient {
	this.httpClient = httpClient
	return this
}

func (this *RestfulClient) sendRestfulRequestGet(url string) ([]byte, error){
	resp, err := this.httpClient.Get(url)
	if err != nil {
		return nil, fmt.Errorf("http post request:%s error:%s", resp, err)
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read restful response body error:%s", err)
	}

	restResp := &RestfulResp{}
	err = json.Unmarshal(body,restResp)
	if err != nil {
		return nil, fmt.Errorf("json.Unmarshal JsonRestResponse:%s error:%s", body, err)
	}
	if restResp.Error != 0 {
		return nil, fmt.Errorf("sendRestRequest error code:%d desc:%s", restResp.Error, restResp.Desc)
	}
	return restResp.Result,nil
}

func (this *RestfulClient) sendRestfulRequestPost(url string,data string)([]byte, error){
	req := &RestfulReq{
		Action:     "sendrawtransaction" ,
		Version:    "1.0.0",
		Type:       1,
		Data:       data,
	}
	params, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("JsonRestRequest json.Marsha error:%s", err)
	}
	resp, err := this.httpClient.Post(this.addr, "application/json", strings.NewReader(string(params)))
	if err != nil {
		return nil, fmt.Errorf("http post request:%s error:%s", data, err)
	}
	defer resp.Body.Close()
	return nil,nil
}

func getPath(path string) string {
	if (strings.Contains(path,":height")) {
		return strings.Replace(path,":height","",len(path))
	} else if (strings.Contains(path,":hash")) {
		return strings.Replace(path,":hash","",len(path))
	} else if (strings.Contains(path,":key")) {
		return strings.Replace(path,":key","",len(path))
	} else if (strings.Contains(path,":addr")) {
		return strings.Replace(path,":addr","",len(path))
	}
	return path
}

func (this *RestfulClient) GetConnectionCount() (uint32, error) {
	data, err := this.sendRestfulRequestGet(this.addr+ GET_CONN_COUNT)
	if err != nil {
		return 0, fmt.Errorf("sendRestRequest error:%s", err)
	}
	count := uint32(0)
	err = json.Unmarshal(data, &count)
	if err != nil {
		return 0, fmt.Errorf("json.Unmarshal:%s error:%s", data, err)
	}
	return count,nil
}

func (this *RestfulClient) GetGenerateBlockTime() (uint32, error){
	url := this.addr + GET_GEN_BLK_TIME
	data, err := this.sendRestfulRequestGet(url)
	if err != nil {
		return 0, fmt.Errorf("sendRestRequest error:%s", err)
	}
	blocktime := uint32(0)
	err = json.Unmarshal(data, &blocktime)
	if err != nil {
		return 0, fmt.Errorf("json.Unmarshal:%s error:%s", data, err)
	}
	return blocktime,nil
}


func (this *RestfulClient) GetBlockByHeight(height int) (*types.Block, error) {
	url := this.addr + getPath(GET_BLK_BY_HEIGHT) + strconv.Itoa(height)
	data, err := this.sendRestfulRequestGet(url)
	if err != nil {
		return nil, fmt.Errorf("sendRestRequest error:%s", err)
	}
	blockInfo := &types.Block{}
	err = json.Unmarshal(data, blockInfo)
	return blockInfo, nil
}

func (this *RestfulClient) GetBlockByHash(txhash string) (*types.Block, error) {
	url := this.addr + getPath(GET_BLK_BY_HASH) + txhash
	data, err := this.sendRestfulRequestGet(url)
	if err != nil {
		return nil, fmt.Errorf("sendRestRequest error:%s", err)
	}
	blockInfo := &types.Block{}
	err = json.Unmarshal(data, blockInfo)
	return blockInfo, nil
	return nil,nil
}

func (this *RestfulClient) GetBlockHeight() (uint32, error) {
	url := this.addr + GET_BLK_HEIGHT
	data, err := this.sendRestfulRequestGet(url)
	if err != nil {
		return 0, fmt.Errorf("sendRestRequest error:%s", err)
	}
	blockheight := uint32(0)
	err = json.Unmarshal(data, &blockheight)
	if err != nil {
		return 0, fmt.Errorf("json.Unmarshal:%s error:%s", data, err)
	}
	return blockheight,nil
}

func (this *RestfulClient) GetBlockHash(height uint32) (common.Uint256, error) {
	url := this.addr + getPath(GET_BLK_HASH) + strconv.FormatUint(uint64(height), 10)
	data, err := this.sendRestfulRequestGet(url)
	if err != nil {
		return common.Uint256{}, fmt.Errorf("sendRestRequest error:%s", err)
	}
	hexHash := ""
	err = json.Unmarshal(data, &hexHash)
	if err != nil {
		return common.Uint256{}, fmt.Errorf("json.Unmarshal hash:%s error:%s", data,err)
	}
	hash, err := utils.ParseUint256FromHexString(hexHash)
	if err != nil {
		return common.Uint256{}, fmt.Errorf("ParseUint256FromHexString:%s error:%s", data, err)
	}
	return hash, nil
}

func (this *RestfulClient) GetTransactionByHash(txHash common.Uint256) (*types.Transaction, error) {
	url := this.addr + GET_TX + common.ToHexString(txHash.ToArray())
	fmt.Println(common.ToHexString(txHash.ToArray()))
	data, err := this.sendRestfulRequestGet(url)
	if err != nil {
		return nil, fmt.Errorf("sendRestRequest error:%s", err)
	}
	tx := &types.Transaction{}

	err = json.Unmarshal(data,tx)

	if err != nil {
		return nil, fmt.Errorf("json.Unmarshal error:%s", err)
	}
	return tx, nil
}

func (this *RestfulClient) GetContractState(contractaddress common.Address) (*payload.DeployCode, error) {
	url := this.addr + GET_CONTRACT_STATE + contractaddress.ToHexString()
	data, err := this.sendRestfulRequestGet(url)
	if err != nil {
		return nil, fmt.Errorf("sendRestRequest error:%s", err)
	}
	deploycodeinfo := &payload.DeployCode{}
	err = json.Unmarshal(data, deploycodeinfo)
	if err != nil {
		return nil, fmt.Errorf("json.Unmarshal error:%s", err)
	}
	return deploycodeinfo, nil
}

func (this *RestfulClient) GetSmartCodeEventTxsByHeight(height uint64) ([]string, error) {
	url := this.addr + GET_SMTCOCE_EVT_TXS + strconv.FormatUint(height,10)
	data, err := this.sendRestfulRequestGet(url)
	if err != nil {
		return nil, fmt.Errorf("sendRestRequest error:%s", err)
	}
	resp := []string{}
    err = json.Unmarshal(data,&resp)
	fmt.Println(resp)
	return resp, nil
}

func (this *RestfulClient) GetSmartCodeEventByTxHash(txHash common.Uint256) ([]*sdkcom.SmartContactEvent, error){
	return this.GetSmartCodeEventByTxHashStr(hex.EncodeToString(txHash.ToArray()))
}

func (this *RestfulClient) GetSmartCodeEventByTxHashStr(txhash string) ([]*sdkcom.SmartContactEvent, error){
	url := this.addr + GET_SMTCOCE_EVTS + txhash
	data, err := this.sendRestfulRequestGet(url)
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

func (this *RestfulClient) GetBlockHeightByTxHash(txHash common.Uint256) (uint32, error){
	return this.GetBlockHeightByTxHashStr(common.ToHexString(txHash.ToArray()))
}

func (this *RestfulClient) GetBlockHeightByTxHashStr(txHash string) (uint32, error){
    url := this.addr + GET_BLK_HGT_BY_TXHASH + txHash
	data, err := this.sendRestfulRequestGet(url)
	if err != nil {
		return 0, fmt.Errorf("sendRpcRequest error:%s", err)
	}
	resp := uint32(0)
	err = json.Unmarshal(data,&resp)
	if err != nil {
		return 0, fmt.Errorf("json.Unmarshal GetBlockHeightByTxHashStr:%s error:%s", data, err)
	}
	return resp,nil
}

func (this *RestfulClient) GetMerkleProofByTxhash(txHash common.Uint256) (*sdkcom.MerkleProof, error){
	return this.GetMerkleProofByTxhashStr(common.ToHexString(txHash.ToArray()))
}
func (this *RestfulClient) GetMerkleProofByTxhashStr(txHash string) (*sdkcom.MerkleProof, error){
	url := this.addr + GET_MERKLE_PROOF + txHash
	data, err := this.sendRestfulRequestGet(url)
	if err != nil {
		return nil, fmt.Errorf("sendRpcRequest error:%s", err)
	}
	resp := &sdkcom.MerkleProof{}
	err = json.Unmarshal(data,resp)
	if err != nil {
		return nil, fmt.Errorf("json.Unmarshal GetBlockHeightByTxHashStr:%s error:%s", data, err)
	}
	return resp,nil
}

func (this *RestfulClient) getPath(url string) string {

	if strings.Contains(url, strings.TrimRight(GET_BLK_TXS_BY_HEIGHT, ":height")) {
		return GET_BLK_TXS_BY_HEIGHT
	} else if strings.Contains(url, strings.TrimRight(GET_BLK_BY_HEIGHT, ":height")) {
		return GET_BLK_BY_HEIGHT
	} else if strings.Contains(url, strings.TrimRight(GET_BLK_HASH, ":height")) {
		return GET_BLK_HASH
	} else if strings.Contains(url, strings.TrimRight(GET_BLK_BY_HASH, ":hash")) {
		return GET_BLK_BY_HASH
	} else if strings.Contains(url, strings.TrimRight(GET_TX, ":hash")) {
		return GET_TX
	} else if strings.Contains(url, strings.TrimRight(GET_CONTRACT_STATE, ":hash")) {
		return GET_CONTRACT_STATE
	} else if strings.Contains(url, strings.TrimRight(GET_SMTCOCE_EVT_TXS, ":height")) {
		return GET_SMTCOCE_EVT_TXS
	} else if strings.Contains(url, strings.TrimRight(GET_SMTCOCE_EVTS, ":hash")) {
		return GET_SMTCOCE_EVTS
	} else if strings.Contains(url, strings.TrimRight(GET_BLK_HGT_BY_TXHASH, ":hash")) {
		return GET_BLK_HGT_BY_TXHASH
	} else if strings.Contains(url, strings.TrimRight(GET_STORAGE, ":hash/:key")) {
		return GET_STORAGE
	} else if strings.Contains(url, strings.TrimRight(GET_BALANCE, ":addr")) {
		return GET_BALANCE
	} else if strings.Contains(url, strings.TrimRight(GET_MERKLE_PROOF, ":hash")) {
		return GET_MERKLE_PROOF
	}
	return url
}

//SendRawTransaction send a transaction to ontology network, and return hash of the transaction
func (this *RestfulClient) SendRawTransaction(tx *types.Transaction) (common.Uint256, error) {
	var buffer bytes.Buffer
	err := tx.Serialize(&buffer)
	if err != nil {
		return common.Uint256{}, fmt.Errorf("Serialize error:%s", err)
	}
	txData := hex.EncodeToString(buffer.Bytes())
	data, err := this.sendRestfulRequestGet(txData)
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

func (this *RestfulClient) Transfer(token string, from, to *account.Account, amount uint64) (common.Uint256, error) {
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
	var sts []*ont.State
	sts = append(sts, &ont.State{
		From:  from.Address,
		To:    to.Address,
		Value: amount,
	})
	transfers := &ont.Transfers{
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
//Sign to a transaction
func (this *RestfulClient) SignTransaction(tx *types.Transaction, signer *account.Account) error {
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

//Sign sign return the signature to the data of private key
func (this *RestfulClient) sign(data []byte, signer *account.Account) ([]byte, error) {
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

//NewInvokeTransaction return smart contract invoke transaction
func (this *RestfulClient) NewInvokeTransaction(gasLimit *big.Int, vmType vmtypes.VmType, code []byte) *types.Transaction {
	invokePayload := &payload.InvokeCode{
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
		Sigs:       make([]*types.Sig, 0, 0),
	}
	return tx
}



