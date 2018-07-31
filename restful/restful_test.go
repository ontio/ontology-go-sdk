package restful

import (
	"testing"
	sdkcommon "github.com/ontio/ontology-go-sdk/common"
	"fmt"
	"github.com/ontio/ontology-go-sdk/utils"
)

var testRestful *RestfulClient

func init(){
	testRestful = NewRestfulClient(sdkcommon.CRYPTO_SCHEME_DEFAULT)
	testRestful.SetAddress("http://localhost:20334")
}

func TestAll(t *testing.T) {
	TestGetGenerateBlockTime(t)
	TestGetConnectionCount(t)
	TestGetBlockByHeight(t)
	TestGetBlockHeight(t)
	TestGetBlockHash(t)
	TestGetTransactionByHash(t)
	TestGetContractState(t)
	TestGetSmartCodeEventTxsByHeight(t)
	TestGetSmartCodeEventByTxHash(t)
	TestGetBlockHeightByTxHash(t)
	TestGetMerkleProofByTxhash(t)

}

func TestGetGenerateBlockTime(t *testing.T) {
	res, err := testRestful.GetGenerateBlockTime()
	if err != nil {
		t.Errorf("GenerateBlockTime error:%s", err)
		return
	}
	fmt.Printf("TestGetGenerateBlockTime :%v\n", res)
}

func TestGetConnectionCount(t *testing.T) {
	res, err := testRestful.GetConnectionCount()
	if err != nil {
		t.Errorf("GenerateBlockTime error:%s", err)
		return
	}
	fmt.Printf("TestGetGenerateBlockTime :%v\n", res)
}

func TestGetBlockByHeight(t *testing.T) {
	res, err := testRestful.GetBlockByHeight(0)
	if err != nil {
		t.Errorf("GetBlockByHeight error:%s", err)
		return
	}
	fmt.Printf("TestGetBlockByHeight :%v\n", res)
}

func TestGetBlockHeight(t *testing.T) {
	res, err := testRestful.GetBlockHeight()
	if err != nil {
		t.Errorf("GetBlockHeight error:%s", err)
		return
	}
	fmt.Printf("TestGetBlockHeight :%v\n", res)
}

func TestGetBlockHash(t *testing.T) {
	res, err := testRestful.GetBlockHash(0)
	if err != nil {
		t.Errorf("GetBlockHash error:%s", err)
		return
	}
	fmt.Printf("TestGetBlockHash :%v\n", res)
}

func TestGetTransactionByHash(t *testing.T) {
	block, err := testRestful.GetBlockByHeight(0)
	if err != nil {
		t.Errorf("GetBlockByHeight error:%s", err)
		return
	}
	txHash := block.Transactions[0].Hash()
	res, err := testRestful.GetTransactionByHash(txHash)
	if err != nil {
		t.Errorf("TestGetTransactionByHash error:%s", err)
		return
	}
	fmt.Printf("TestGetBlockHash :%v\n", res)
}

func TestGetContractState(t *testing.T) {
	contractAddress := "803ca638069742da4b6871fe3d7f78718eeee78a"
	conAddress, err := utils.ParseAddressFromHexString(contractAddress)
	if err != nil {
		t.Errorf("utils.ParseAddressFromHexString error:%s",err)
		return
	}
	res, err := testRestful.GetContractState(conAddress)
	if err != nil {
		t.Errorf("GetBlockHash error:%s", err)
		return
	}
	fmt.Printf("TestGetBlockHash :%v\n", res)
}

func TestGetSmartCodeEventTxsByHeight(t *testing.T) {
	res, err := testRestful.GetSmartCodeEventTxsByHeight(0)
	if err != nil {
		t.Errorf("GetSmartCodeEventTxsByHeight error:%s", err)
		return
	}
	fmt.Printf("TestGetSmartCodeEventTxsByHeight :%v\n", res)
}

func TestGetSmartCodeEventByTxHash(t *testing.T) {
	ontInitTxHash := "3c2b49d988490bce743939cc2f2208ea43197fb004b64ff700f3a60647d49147"
	ontInitTx, err := utils.ParseUint256FromHexString(ontInitTxHash)
	res, err := testRestful.GetSmartCodeEventByTxHash(ontInitTx)
	if err != nil {
		t.Errorf("GetSmartCodeEventTxsByHeight error:%s", err)
		return
	}
	fmt.Printf("TestGetSmartCodeEventTxsByHeight :%v\n", res)
}

func TestGetBlockHeightByTxHash(t *testing.T) {
	tx,_ := utils.ParseUint256FromHexString("8fe5e2c28f6873ae428824a71b39f14f644fc23b49adb77a0b985b0fb8494d04")
	res, err := testRestful.GetBlockHeightByTxHash(tx)
	if err != nil {
		t.Errorf("GetBlockHeightByTxHash error:%s", err)
		return
	}
	fmt.Println(res)
}

func TestGetMerkleProofByTxhash(t *testing.T) {
	tx,_ := utils.ParseUint256FromHexString("8fe5e2c28f6873ae428824a71b39f14f644fc23b49adb77a0b985b0fb8494d04")
	res, err := testRestful.GetMerkleProofByTxhash(tx)
	if err != nil {
		t.Errorf("GetBlockHeightByTxHash error:%s", err)
		return
	}
	fmt.Println(res)
}

