package rpc

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/ontio/ontology-crypto/keypair"
	sig "github.com/ontio/ontology-crypto/signature"
	sdkcom "github.com/ontio/ontology-go-sdk/common"
	"github.com/ontio/ontology-go-sdk/utils"
	"github.com/ontio/ontology/account"
	"github.com/ontio/ontology/common"
	"github.com/ontio/ontology/core/genesis"
	"github.com/ontio/ontology/core/payload"
	"github.com/ontio/ontology/core/types"
	"github.com/ontio/ontology/smartcontract/service/native/states"
	"github.com/ontio/ontology/vm/neovm"
	vmtypes "github.com/ontio/ontology/vm/types"
	"io/ioutil"
	"math/big"
	"net/http"
	"strings"
	"sync/atomic"
	"time"
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

//Create RpcClient instance
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

func (this *RpcClient) SetCryptScheme(cryptScheme string) {
	this.cryptScheme = cryptScheme
}

func (this *RpcClient) SetAddress(addr string) *RpcClient {
	this.addr = addr
	return this
}

func (this *RpcClient) SetHttpClient(httpClient *http.Client) *RpcClient {
	this.httpClient = httpClient
	return this
}

func (this *RpcClient) SetWebSocketAddress(wsAddr string) {
	this.wsAddr = wsAddr
}

//Get ontology version
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

//Get block of ontology by block hash
func (this *RpcClient) GetBlockByHash(hash common.Uint256) (*types.Block, error) {
	data, err := this.sendRpcRequest(RPC_GET_BLOCK, []interface{}{hex.EncodeToString(hash.ToArray())})
	if err != nil {
		return nil, fmt.Errorf("sendRpcRequest error:%s", err)
	}
	block := &types.Block{}
	buf := bytes.NewBuffer(data)
	err = block.Deserialize(buf)
	if err != nil {
		return nil, err
	}
	return block, nil
}

//Get block of ontology by block height
func (this *RpcClient) GetBlockByHeight(height uint32) (*types.Block, error) {
	data, err := this.sendRpcRequest(RPC_GET_BLOCK, []interface{}{height})
	if err != nil {
		return nil, fmt.Errorf("sendRpcRequest error:%s", err)
	}
	block := &types.Block{}
	buf := bytes.NewBuffer(data)
	err = block.Deserialize(buf)
	if err != nil {
		return nil, err
	}
	return block, nil
}

//Get total block count of ontology
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

//Get current block hash of ontology
func (this *RpcClient) GetCurrentBlockHash() (common.Uint256, error) {
	data, err := this.sendRpcRequest(RPC_GET_CURRENT_BLOCK_HASH, []interface{}{})
	if err != nil {
		return common.Uint256{}, fmt.Errorf("sendRpcRequest error:%s", err)
	}
	hash, err := utils.ParseUint256FromHexString(string(data))
	if err != nil {
		return common.Uint256{}, fmt.Errorf("ParseUint256FromHexString:%s error:%s", data, err)
	}
	return hash, nil
}

//Get ontology block hash by block height
func (this *RpcClient) GetBlockHash(height uint32) (common.Uint256, error) {
	data, err := this.sendRpcRequest(RPC_GET_BLOCK_HASH, []interface{}{height})
	if err != nil {
		return common.Uint256{}, fmt.Errorf("sendRpcRequest error:%s", err)
	}
	hash, err := utils.ParseUint256FromHexString(string(data))
	if err != nil {
		return common.Uint256{}, fmt.Errorf("ParseUint256FromHexString:%s error:%s", data, err)
	}
	return hash, nil
}

//Get ont and ong balance of a ontology address
func (this *RpcClient) GetBalance(addr common.Address) (*sdkcom.Balance, error) {
	return this.GetBalanceWithBase58(addr.ToBase58())
}

//Get ont and ong balance of a ontology address in base58 address
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
		Ont: ont,
		Ong: ong,
	}, nil
}

//Get smart contract storage item.
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
	v := string(data)
	value, err := hex.DecodeString(v)
	if err != nil {
		return nil, fmt.Errorf("hex.DecodeString:%s error:%s", v, err)
	}
	return value, nil
}

//Get smart contract event execute by invoke transaction
func (this *RpcClient) GetSmartContractEvent(txHash common.Uint256) ([]*sdkcom.SmartContactEvent, error) {
	data, err := this.sendRpcRequest(RPC_GET_SMART_CONTRACT_EVENT, []interface{}{hex.EncodeToString(txHash.ToArray())})
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

//Get transaction by transaction hash in ontology
func (this *RpcClient) GetRawTransaction(txHash common.Uint256) (*types.Transaction, error) {
	data, err := this.sendRpcRequest(RPC_GET_TRANSACTION, []interface{}{hex.EncodeToString(txHash.ToArray())})
	if err != nil {
		return nil, fmt.Errorf("sendRpcRequest error:%s", err)
	}
	buf := bytes.NewBuffer(data)
	tx := &types.Transaction{}
	err = tx.Deserialize(buf)
	if err != nil {
		return nil, err
	}
	return tx, nil
}

//Get smart contract deploy in ontology
func (this *RpcClient) GetSmartContract(smartContractAddress common.Address) (*payload.DeployCode, error) {
	data, err := this.sendRpcRequest(RPC_GET_SMART_CONTRACT, []interface{}{hex.EncodeToString(smartContractAddress[:])})
	if err != nil {
		return nil, fmt.Errorf("sendRpcRequest error:%s", err)
	}
	deploy := &payload.DeployCode{}
	buf := bytes.NewReader(data)
	err = deploy.Deserialize(buf)
	if err != nil {
		return nil, err
	}
	return deploy, nil
}

//Wait ontology generate block. Default wait 2 blocks. return timeout error when there is no block generate in some time.
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
func (this *RpcClient) Transfer(token string, from, to *account.Account, amount *big.Int, isPreExec ...bool) (common.Uint256, error) {
	isPre := false
	if len(isPreExec) > 0 && isPreExec[0] {
		isPre = true
	}
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
	crt := &states.Contract{
		Address: contractAddress,
		Method:  "transfer",
		Args:    buf.Bytes(),
	}
	buf.Reset()
	err = crt.Serialize(buf)
	if err != nil {
		return common.Uint256{}, fmt.Errorf("Serialize contract error:%s", err)
	}

	invokeTx := this.NewInvokeTransaction(new(big.Int).SetInt64(0), vmtypes.Native, buf.Bytes())
	err = this.SignTransaction(invokeTx, from)
	if err != nil {
		return common.Uint256{}, fmt.Errorf("SignTransaction error:%s", err)
	}
	txHash, err := this.SendRawTransaction(invokeTx, isPre)
	if err != nil {
		return common.Uint256{}, fmt.Errorf("SendTransaction error:%s", err)
	}
	return txHash, nil
}

//Deploy smart contract to ontology
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
		return common.Uint256{}, fmt.Errorf("hex.DecodeString error:%s", code, err)
	}
	tx := this.NewDeployCodeTransaction(vmType, c, needStorage, name, version, author, email, desc)

	err = this.SignTransaction(tx, singer)
	if err != nil {
		return common.Uint256{}, err
	}
	txHash, err := this.SendRawTransaction(tx, false)
	if err != nil {
		return common.Uint256{}, fmt.Errorf("SendRawTransaction error:%s", err)
	}
	return txHash, nil
}

//Sign to transaction
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

//Build neovm invoke param code
func (this *RpcClient) buildNVMParamInter(builder *neovm.ParamsBuilder, smartContractParams []interface{}) error {
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
			err := this.buildNVMParamInter(builder, v)
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

//Build NeoVM Invoke code
func (this *RpcClient) BuildNeoVMInvokeCode(smartContractAddress common.Address, params []interface{}) ([]byte, error) {
	builder := neovm.NewParamsBuilder(new(bytes.Buffer))
	err := this.buildNVMParamInter(builder, params)
	if err != nil {
		return nil, err
	}

	buf := bytes.NewBuffer(nil)
	buf.Write(builder.ToArray())
	buf.Write(append([]byte{0x67}, smartContractAddress[:]...))
	return buf.Bytes(), nil
}

//Invoke neo vm smart contract
func (this *RpcClient) InvokeNeoVMSmartContract(
	siger *account.Account,
	gasLimit *big.Int,
	smartcodeAddress common.Address,
	params []interface{},
	isPreExec ...bool) (common.Uint256, error) {
	code, err := this.BuildNeoVMInvokeCode(smartcodeAddress, params)
	if err != nil {
		return common.Uint256{}, fmt.Errorf("BuildNVMInvokeCode error:%s", err)
	}
	tx := this.NewInvokeTransaction(gasLimit, vmtypes.NEOVM, code)
	err = this.SignTransaction(tx, siger)
	if err != nil {
		return common.Uint256{}, nil
	}
	isPre := false
	if len(isPreExec) > 0 && isPreExec[0] {
		isPre = true
	}
	return this.SendRawTransaction(tx, isPre)
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

//multi sign to a transaction
func (this *RpcClient) MultiSignTransaction(tx *types.Transaction, m uint8, signers []*account.Account) error {
	if len(signers) == 0 {
		return fmt.Errorf("not enough signer")
	}
	n := len(signers)
	if int(m) > n {
		return fmt.Errorf("M:%d should smaller than N:%", m, n)
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

//Send a transaction to ontology network
//Params isPreExec is use for prepare execut in smart contract invoke transaction
func (this *RpcClient) SendRawTransaction(tx *types.Transaction, isPreExec bool) (common.Uint256, error) {
	var buffer bytes.Buffer
	err := tx.Serialize(&buffer)
	if err != nil {
		return common.Uint256{}, fmt.Errorf("Serialize error:%s", err)
	}
	txData := hex.EncodeToString(buffer.Bytes())
	params := []interface{}{txData}
	if isPreExec {
		params = append(params, 1)
	}
	data, err := this.sendRpcRequest(RPC_SEND_TRANSACTION, params)
	if err != nil {
		return common.Uint256{}, err
	}
	hash, err := utils.ParseUint256FromHexString(string(data))
	if err != nil {
		return common.Uint256{}, fmt.Errorf("ParseUint256FromHexString:%s error:%s", data, err)
	}
	return hash, nil
}

//Create a smart contract deploy transaction instance
func (this *RpcClient) NewDeployCodeTransaction(
	vmType vmtypes.VmType,
	code []byte,
	needStorage bool,
	name, version, author, email, desc string) *types.Transaction {

	vmCode := &vmtypes.VmCode{
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

//Create smart contract invoke transaction
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
	return fmt.Sprint("%d", atomic.AddUint64(&this.qid, 1))
}

//Send Rpc request to ontology
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
