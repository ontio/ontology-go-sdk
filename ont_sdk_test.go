package ontology_go_sdk

import (
	"fmt"
	"strconv"
	"testing"
	"time"
)

var (
	testOntSdk   *OntologySdk
	testWallet   *Wallet
	testPasswd   = []byte("123456")
	testDefAcc   *Account
	testGasPrice = uint64(0)
	testGasLimit = uint64(20000)
)

func TestMain(m *testing.M) {
	testOntSdk = NewOntologySdk()
	testOntSdk.NewRpcClient().SetAddress("http://localhost:20336")

	var err error
	wallet,err := testOntSdk.CreateWallet("./wallet.dat")
	if err != nil {
		return
	}
	wallet.NewDefaultSettingAccount(testPasswd)
	wallet.Save()
	testWallet, err = testOntSdk.OpenWallet("./wallet.dat")
	if err != nil {
		fmt.Printf("account.Open error:%s\n", err)
		return
	}
	testDefAcc, err = testWallet.GetDefaultAccount(testPasswd)
	if err != nil {
		fmt.Printf("GetDefaultAccount error:%s\n", err)
		return
	}

	//ws := testOntSdk.NewWebSocketClient()
	//err = ws.Connect("ws://localhost:20335")
	//if err != nil {
	//	fmt.Printf("Connect ws error:%s", err)
	//	return
	//}
	//m.Run()
}

func TestOntologySdk_CreateWallet(t *testing.T) {
	testOntSdk.CreateWallet("./wallet2.dat")
}
func TestOnt_Transfer(t *testing.T) {
	txHash, err := testOntSdk.Native.Ont.Transfer(testGasPrice, testGasLimit, testDefAcc, testDefAcc.Address, 1)
	if err != nil {
		t.Errorf("NewTransferTransaction error:%s", err)
		return
	}
	testOntSdk.WaitForGenerateBlock(30*time.Second, 1)
	evts, err := testOntSdk.GetSmartContractEvent(txHash.ToHexString())
	if err != nil {
		t.Errorf("GetSmartContractEvent error:%s", err)
		return
	}
	fmt.Printf("TxHash:%s\n", txHash.ToHexString())
	fmt.Printf("State:%d\n", evts.State)
	fmt.Printf("GasConsume:%d\n", evts.GasConsumed)
	for _, notify := range evts.Notify {
		fmt.Printf("ContractAddress:%s\n", notify.ContractAddress)
		fmt.Printf("States:%+v\n", notify.States)
	}
}

func TestOng_WithDrawONG(t *testing.T) {
	unboundONG, err := testOntSdk.Native.Ong.UnboundONG(testDefAcc.Address)
	if err != nil {
		t.Errorf("UnboundONG error:%s", err)
		return
	}
	fmt.Printf("Address:%s UnboundONG:%d\n", testDefAcc.Address.ToBase58(), unboundONG)
	_, err = testOntSdk.Native.Ong.WithdrawONG(0, 20000, testDefAcc, unboundONG)
	if err != nil {
		t.Errorf("WithDrawONG error:%s", err)
		return
	}
	fmt.Printf("Address:%s WithDrawONG amount:%d success\n", testDefAcc.Address.ToBase58(), unboundONG)
}

func TestGlobalParam_GetGlobalParams(t *testing.T) {
	gasPrice := "gasPrice"
	params := []string{gasPrice}
	results, err := testOntSdk.Native.GlobalParams.GetGlobalParams(params)
	if err != nil {
		t.Errorf("GetGlobalParams:%+v error:%s", params, err)
		return
	}
	fmt.Printf("Params:%s Value:%v\n", gasPrice, results[gasPrice])
}

func TestGlobalParam_SetGlobalParams(t *testing.T) {
	gasPrice := "gasPrice"
	globalParams, err := testOntSdk.Native.GlobalParams.GetGlobalParams([]string{gasPrice})
	if err != nil {
		t.Errorf("GetGlobalParams error:%s", err)
		return
	}
	gasPriceValue, err := strconv.Atoi(globalParams[gasPrice])
	if err != nil {
		t.Errorf("Get prama value error:%s", err)
		return
	}
	_, err = testOntSdk.Native.GlobalParams.SetGlobalParams(testGasPrice, testGasLimit, testDefAcc, map[string]string{gasPrice: strconv.Itoa(gasPriceValue + 1)})
	if err != nil {
		t.Errorf("SetGlobalParams error:%s", err)
		return
	}
	testOntSdk.WaitForGenerateBlock(30*time.Second, 1)
	globalParams, err = testOntSdk.Native.GlobalParams.GetGlobalParams([]string{gasPrice})
	if err != nil {
		t.Errorf("GetGlobalParams error:%s", err)
		return
	}
	gasPriceValueAfter, err := strconv.Atoi(globalParams[gasPrice])
	if err != nil {
		t.Errorf("Get prama value error:%s", err)
		return
	}
	fmt.Printf("After set params gasPrice:%d\n", gasPriceValueAfter)
}

func TestWsScribeEvent(t *testing.T) {
	wsClient := testOntSdk.ClientMgr.GetWebSocketClient()
	err := wsClient.SubscribeEvent()
	if err != nil {
		t.Errorf("SubscribeTxHash error:%s", err)
		return
	}
	defer wsClient.UnsubscribeTxHash()

	actionCh := wsClient.GetActionCh()
	timer := time.NewTimer(time.Minute * 3)
	for {
		select {
		case <-timer.C:
			return
		case action := <-actionCh:
			fmt.Printf("Action:%s\n", action.Action)
			fmt.Printf("Result:%s\n", action.Result)
		}
	}
}

func TestWsTransfer(t *testing.T){
	wsClient := testOntSdk.ClientMgr.GetWebSocketClient()
	testOntSdk.ClientMgr.SetDefaultClient(wsClient)
	txHash, err := testOntSdk.Native.Ont.Transfer(testGasPrice, testGasLimit, testDefAcc, testDefAcc.Address, 1)
	if err != nil {
		t.Errorf("NewTransferTransaction error:%s", err)
		return
	}
	testOntSdk.WaitForGenerateBlock(30*time.Second, 1)
	evts, err := testOntSdk.GetSmartContractEvent(txHash.ToHexString())
	if err != nil {
		t.Errorf("GetSmartContractEvent error:%s", err)
		return
	}
	fmt.Printf("TxHash:%s\n", txHash.ToHexString())
	fmt.Printf("State:%d\n", evts.State)
	fmt.Printf("GasConsume:%d\n", evts.GasConsumed)
	for _, notify := range evts.Notify {
		fmt.Printf("ContractAddress:%s\n", notify.ContractAddress)
		fmt.Printf("States:%+v\n", notify.States)
	}
}