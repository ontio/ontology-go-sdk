package ws

import (
	"bytes"
	"fmt"
	"github.com/ontio/ontology-crypto/keypair"
	s "github.com/ontio/ontology-crypto/signature"
	sdkcom "github.com/ontio/ontology-go-sdk/common"
	"github.com/ontio/ontology-go-sdk/utils"
	"github.com/ontio/ontology/account"
	"github.com/ontio/ontology/common/constants"
	"github.com/ontio/ontology/common/serialization"
	"github.com/ontio/ontology/core/payload"
	"github.com/ontio/ontology/core/types"
	"github.com/ontio/ontology/smartcontract/service/native/ont"
	nvutils "github.com/ontio/ontology/smartcontract/service/native/utils"
	"testing"
	"time"
)

var (
	testWSClient *WSClient
	testWallet   account.Client
	testPasswd   = []byte("wangbing")
)

func TestMain(t *testing.M) {
	testWSClient = NewWSClient()
	err := testWSClient.Connect("ws://localhost:20335")
	if err != nil {
		fmt.Printf("Connect error:%s\n", err)
		return
	}
	walletFile := "./wallet.dat"
	testWallet, err = account.Open(walletFile)
	if err != nil {
		fmt.Errorf("wallet open error:%s", err)
		return
	}
	accMeta := testWallet.GetAccountMetadataByLabel("t")
	if accMeta == nil {
		_, err = testWallet.NewAccount("t", keypair.PK_ECDSA, keypair.P256, s.SHA256withECDSA, testPasswd)
		if err != nil {
			fmt.Errorf("NewAccount error:%s", err)
			return
		}
	}
	t.Run()
	err = testWSClient.Close()
	if err != nil {
		fmt.Printf("Close error:%s\n", err)
		return
	}
}

func TestSubBlock(t *testing.T) {
	fmt.Printf("TestSubBlock\n")
	count := 2
	err := testWSClient.SubscribeBlock()
	if err != nil {
		t.Errorf("SubscribeBlock error:%s", err)
		return
	}
	defer func() {
		err = testWSClient.UnsubscribeBlock()
		if err != nil {
			t.Errorf("UnsubscribeBlock error:%s", err)
			return
		}
	}()
	for i := count; i > 0; {
		select {
		case act := <-testWSClient.GetActionCh():
			if act.Action != WS_SUBSCRIBE_ACTION_BLOCK {
				continue
			}
			block := act.Result.(*types.Block)
			blockHash := block.Hash()
			fmt.Printf("Block Height:%d BlockHash:%s\n", block.Header.Height, blockHash.ToHexString())
			i--
		}
	}
}

func TestSubBlockTxHashes(t *testing.T) {
	fmt.Printf("TestSubBlockTxHashes\n")
	count := 2
	err := testWSClient.SubscribeTxHash()
	if err != nil {
		t.Errorf("SubscribeTxHash error:%s", err)
		return
	}
	defer func() {
		err = testWSClient.UnsubscribeTxHash()
		if err != nil {
			t.Errorf("UnsubscribeTxHash error:%s", err)
			return
		}
	}()
	for i := count; i > 0; {
		select {
		case act := <-testWSClient.GetActionCh():
			if act.Action != WS_SUBSCRIBE_ACTION_BLOCK_TX_HASH {
				continue
			}
			blockTxHash := act.Result.(*sdkcom.BlockTxHashes)
			fmt.Printf("Block Height:%d BlockHash:%s\n", blockTxHash.Height, blockTxHash.Hash.ToHexString())
			for _, txHash := range blockTxHash.Transactions {
				fmt.Printf("TxHash:%s\n", txHash.ToHexString())
			}
			i--
		}
	}
}

func TestSubEvent(t *testing.T) {
	fmt.Printf("TestSubEvent\n")
	err := testWSClient.SubscribeEvent()
	if err != nil {
		t.Errorf("SubscribeEvent error:%s", err)
		return
	}

	//err = testWSClient.AddContractFilterWithHexString("0100000000000000000000000000000000000000")
	//if err != nil {
	//	t.Errorf("AddContractFilterWithHexString error:%s", err)
	//	return
	//}
	defer func() {
		err = testWSClient.UnsubscribeEvent()
		if err != nil {
			t.Errorf("UnsubscribeEvent error:%s", err)
			return
		}
	}()
	exitCh := make(chan interface{}, 0)
	go func() {
		for {
			select {
			case <-exitCh:
				return
			case act := <-testWSClient.GetActionCh():
				switch act.Action {
				case WS_SUBSCRIBE_ACTION_EVENT_NOTIFY:
					evt := act.Result.(*sdkcom.SmartContactEvent)
					fmt.Printf("Event TxHash:%s State:%d GasConsumed:%d\n", evt.TxHash, evt.State, evt.GasConsumed)
					for i, notify := range evt.Notify {
						fmt.Printf("Notify:%d %+v\n", i, notify)
					}
				case WS_SUBSCRIBE_ACTION_EVENT_LOG:
					fmt.Printf("%+v\n", act.Result)
				}
			}
		}
	}()
	time.Sleep(30 * time.Second)
	close(exitCh)
}

func TestGetVersion(t *testing.T) {
	version, err := testWSClient.GetVersion()
	if err != nil {
		t.Errorf("GetVersion error:%s", err)
		return
	}
	fmt.Printf("Version:%s\n", version)
}

func TestGetMemPoolTxCount(t *testing.T) {
	count, err := testWSClient.GetMemPoolTxCount()
	if err != nil {
		t.Errorf("GetMemPoolTxCount error:%s", err)
		return
	}
	fmt.Printf("MemPoolTxCount:%+v\n", count)
}

func TestGetMemPoolTxState(t *testing.T) {
	defAcc, err := testWallet.GetDefaultAccount(testPasswd)
	if err != nil {
		t.Errorf("GetDefaultAccount error:%s", err)
		return
	}
	tx, err := testWSClient.NewTransferTransaction(0, 20000, "ont", defAcc.Address, defAcc.Address, 10)
	if err != nil {
		t.Errorf("NewTransferTransaction error:%s", err)
		return
	}
	err = testWSClient.SignToTransaction(tx, defAcc)
	if err != nil {
		t.Errorf("SignToTransaction error:%s", err)
		return
	}
	wsReq, err := testWSClient.AsyncSendRawTransaction(tx)
	if err != nil {
		t.Errorf("AsyncSendRawTransaction error:%s", err)
		return
	}
	txHash := tx.Hash()
	state, err := testWSClient.GetMemPoolTxState(txHash)
	if err != nil {
		t.Errorf("GetMemPoolTxState error:%s", err)
		return
	}
	fmt.Printf("Befor exec:\n")
	for _, stateItem := range state.State {
		fmt.Printf("State:%+v\n", stateItem)
	}
	<-wsReq.ResCh
	state, err = testWSClient.GetMemPoolTxState(txHash)
	if err != nil {
		t.Errorf("GetMemPoolTxState error:%s", err)
		return
	}
	fmt.Printf("After exec:\n")
	for _, stateItem := range state.State {
		fmt.Printf("State:%+v\n", stateItem)
	}
}

func TestGetBlockByHash(t *testing.T) {
	blockHash, err := testWSClient.GetBlockHash(0)
	if err != nil {
		t.Errorf("GetBlockHash error:%s", err)
		return
	}
	block, err := testWSClient.GetBlockByHash(blockHash)
	if err != nil {
		t.Errorf("GetBlockByHash error:%s", err)
		return
	}
	fmt.Printf("TestGetBlockByHash BlockHeight:%d BlockHash:%x\n", block.Header.Height, block.Hash())
}

func TestGetBlockByHeight(t *testing.T) {
	block, err := testWSClient.GetBlockByHeight(0)
	if err != nil {
		t.Errorf("GetBlockByHash error:%s", err)
		return
	}
	fmt.Printf("TestGetBlockByHeight BlockHeight:%d BlockHash:%x\n", block.Header.Height, block.Hash())
}

func TestGetCurrentBlockHeight(t *testing.T) {
	count, err := testWSClient.GetCurrentBlockHeight()
	if err != nil {
		t.Errorf("GetCurrentBlockHeight error:%s", err)
		return
	}
	fmt.Printf("TestGetCurrentBlockHeight BlockCount:%d\n", count)
}

func TestGetCurrentBlockHash(t *testing.T) {
	blockHash, err := testWSClient.GetCurrentBlockHash()
	if err != nil {
		t.Errorf("GetCurrentBlockHash error:%s", err)
		return
	}
	fmt.Printf("GetCurrentBlockHash %x\n", blockHash)
}

func TestGetBlockHash(t *testing.T) {
	blockHash, err := testWSClient.GetBlockHash(0)
	if err != nil {
		t.Errorf("GetBlockHash error:%s", err)
		return
	}
	fmt.Printf("TestGetBlockHash %x\n", blockHash)
}

func TestGetBalance(t *testing.T) {
	defAcc, err := testWallet.GetDefaultAccount(testPasswd)
	if err != nil {
		t.Errorf("GetDefaultAccount error:%s", err)
		return
	}
	balance, err := testWSClient.GetBalance(defAcc.Address)
	if err != nil {
		t.Errorf("GetBalance error:%s", err)
		return
	}
	fmt.Printf("TestGetBalance ONT:%d ONG:%d\n", balance.Ont, balance.Ong)
}

func TestGetStorage(t *testing.T) {
	value, err := testWSClient.GetStorage(nvutils.OntContractAddress, []byte(ont.TOTALSUPPLY_NAME))
	if err != nil {
		t.Errorf("TestGetStorage error:%s", err)
		return
	}
	if value == nil {
		t.Errorf("TestGetStorage value is nil")
		return
	}
	totalSupply, err := serialization.ReadUint64(bytes.NewReader(value))
	if err != nil {
		t.Errorf("TestGetStorage serialization.ReadUint64 error:%s", err)
		return
	}
	if totalSupply != constants.ONT_TOTAL_SUPPLY {
		t.Errorf("TestGetStorage totalSupply %d != %d", totalSupply, constants.ONT_TOTAL_SUPPLY)
		return
	}
	fmt.Printf("TestGetStorage %d\n", totalSupply)
}

func TestGetSmartContractEvent(t *testing.T) {
	events, err := testWSClient.GetSmartContractEventByBlock(0)
	if err != nil {
		t.Errorf("GetSmartContractEventByBlock error:%s", err)
		return
	}

	scEvt, err := testWSClient.GetSmartContractEventWithHexString(events[0].TxHash)
	if err != nil {
		t.Errorf("GetSmartContractEvent error:%s", err)
		return
	}
	//Sample:
	//{
	//	"TxHash": "a0cdac22f3e0554ec41bd4e8a2d151b6a6e178fcb194b449cfb13f1f22dbe8e7",
	//	"State": 1,
	//	"GasConsumed": 0,
	//	"Notify": [
	//		{
	//			"ContractAddress": "ff00000000000000000000000000000000000001",
	//			"States": [
	//				"transfer",
	//				"TA9PGG2Ze5RDYXy8mYjo9Brw2WLzthncH2",
	//				"TA4WwfrGEjcrRPQCCp6nS2f9ymRHmzeCgj",
	//				10
	//			]
	//		}
	//	]
	//}

	fmt.Printf(" TxHash:%s\n", scEvt.TxHash)
	fmt.Printf(" State:%d\n", scEvt.State)
	fmt.Printf(" GasConsumed:%d\n", scEvt.GasConsumed)
	for _, notify := range scEvt.Notify {
		fmt.Printf(" SmartContractAddress:%s\n", notify.ContractAddress)
		states := notify.States.([]interface{})
		name := states[0].(string)
		from := states[1].(string)
		to := states[2].(string)
		value := states[3].(float64)
		fmt.Printf(" State Name:%s from:%s to:%s value:%d\n", name, from, to, int(value))
	}
}

func TestGetRawTransaction(t *testing.T) {
	block, err := testWSClient.GetBlockByHeight(0)
	if err != nil {
		t.Errorf("GetBlockByHeight error:%s", err)
		return
	}
	//The first transaction is ont deploy transaction
	ont := block.Transactions[0]
	tx, err := testWSClient.GetRawTransaction(ont.Hash())
	if err != nil {
		t.Errorf("GetRawTransaction error:%s", err)
		return
	}
	fmt.Printf("TestGetRawTransaction TxHash:%x\n", tx.Hash())
}

func TestGetSmartContract(t *testing.T) {
	block, err := testWSClient.GetBlockByHeight(0)
	if err != nil {
		t.Errorf("GetBlockByHeight error:%s", err)
		return
	}
	//The first transaction is ont deploy transaction
	ont := block.Transactions[0]
	payload := ont.Payload.(*payload.DeployCode)

	contractAddress := types.AddressFromVmCode(payload.Code)
	contract, err := testWSClient.GetSmartContract(contractAddress)
	if err != nil {
		t.Errorf("GetSmartContract error:%s", err)
		return
	}
	fmt.Printf("TestGetSmartContract:\n Code:%x\n Author:%s\n Verson:%s\n NeedStorage:%v\n Email:%s\n Description:%s\n",
		contract.Code, contract.Author, contract.Version, contract.NeedStorage, contract.Email, contract.Description)
}

//func TestGetGenerateBlockTime(t *testing.T) {
//	genTime, err := testWSClient.GetGenerateBlockTime()
//	if err != nil {
//		t.Errorf("GetGenerateBlockTime error:%s", err)
//		return
//	}
//	fmt.Printf("TestGetGenerateBlockTime:%d\n", genTime)
//}

func TestMerkleProof(t *testing.T) {
	block, err := testWSClient.GetBlockByHeight(0)
	if err != nil {
		t.Errorf("GetBlockByHeight error:%s", err)
		return
	}
	txHash := block.Transactions[0].Hash()

	proof, err := testWSClient.GetMerkleProof(txHash)
	if err != nil {
		t.Errorf("GetMerkleProof error:%s", err)
		return
	}
	fmt.Printf("TestMerkleProof %+v\n", proof)
}

func TestDeployContract(t *testing.T) {
	signer, err := testWallet.GetDefaultAccount(testPasswd)
	if err != nil {
		t.Errorf("TestDeployNeoVMContract GetDefaultAccount error:%s\n", err)
		return
	}
	/*
		using Neo.SmartContract.Framework;
		using Neo.SmartContract.Framework.Services.Neo;
		using Neo.SmartContract.Framework.Services.System;
		using System;
		using System.ComponentModel;
		using System.Numerics;
		namespace NeoContract
		{
		   public class Contract1 : SmartContract
		   {
			   public static object Main()
			   {
				   Storage.Put(Storage.CurrentContext, "Hello", "World");
				   return Storage.Get(Storage.CurrentContext, "Hello").AsString();
			   }
		   }
		}
	*/
	//contractCode was compiled by compiler
	contractCode := "51c56b616168164e656f2e53746f726167652e476574436f6e746578740548656c6c6f05576f726c64615272680f4e656f" +
		"2e53746f726167652e507574616168164e656f2e53746f726167652e476574436f6e746578740548656c6c6f617c680f4e656f2e53746f" +
		"726167652e4765746c766b00527ac46203006c766b00c3616c7566"

	txHash, err := testWSClient.DeploySmartContract(
		0, 20000000,
		signer,
		true,
		contractCode,
		"TestDeploySmartContract",
		"1.0",
		"",
		"",
		"",
	)

	if err != nil {
		t.Errorf("TestDeployContract DeploySmartContract error:%s\n", err)
		return
	}
	//WaitForGenerateBlock, ensure contract was be deploy in block
	_, err = testWSClient.WaitForGenerateBlock(30*time.Second, 1)
	if err != nil {
		t.Errorf("TestDeploySmartContract WaitForGenerateBlock error:%s", err)
		return
	}
	fmt.Printf("TestDeployContract TxHash:%x\n", txHash)
}

func TestInvokeNeoVMContract(t *testing.T) {
	//contractCode was compiled by compiler
	contractCode := "51c56b616168164e656f2e53746f726167652e476574436f6e746578740548656c6c6f05576f726c64615272680f4e656f" +
		"2e53746f726167652e507574616168164e656f2e53746f726167652e476574436f6e746578740548656c6c6f617c680f4e656f2e53746f" +
		"726167652e4765746c766b00527ac46203006c766b00c3616c7566"
	contractCodeAddress, err := utils.GetContractAddress(contractCode)
	if err != nil {
		t.Errorf("GetAssetAddress error:%s", err)
		return
	}
	signer, err := testWallet.GetDefaultAccount(testPasswd)
	if err != nil {
		t.Errorf("TestInvokeNeoVMContract GetDefaultAccount error:%s", err)
		return
	}

	txHash, err := testWSClient.InvokeNeoVMContract(0, 20000, signer, contractCodeAddress, []interface{}{})
	if err != nil {
		t.Errorf("TestInvokeNeoVMContract InvokeNeoVMContract error:%s", err)
		return
	}

	fmt.Printf("TestInvokeNeoVMContract TxHash:%x\n", txHash)
}

func TestPrepareInvokeNativeContract(t *testing.T) {
	result, err := testWSClient.PrepareInvokeNativeContract(nvutils.OntContractAddress, 0, "name", nil)
	if err != nil {
		t.Errorf("PrepareInvokeNativeContract error:%s", err)
		return
	}
	fmt.Printf("%s\n", result.Result)
}

func TestWaitForGenerateBlock(t *testing.T) {
	blockHeight, err := testWSClient.GetCurrentBlockHeight()
	if err != nil {
		t.Errorf("GetCurrentBlockHeight error:%s", err)
		return
	}
	_, err = testWSClient.WaitForGenerateBlock(30*time.Second, 1)
	if err != nil {
		t.Errorf("WaitForGenerateBlock error:%s", err)
		return
	}
	blockHeightAfter, err := testWSClient.GetCurrentBlockHeight()
	if err != nil {
		t.Errorf("GetCurrentBlockHeight error:%s", err)
		return
	}
	if blockHeightAfter <= blockHeight {
		t.Errorf("TestWaitForGenerateBlock failed block height:%d <= %d", blockHeightAfter, blockHeight)
		return
	}
	fmt.Printf("Block Height before:%d after:%d\n", blockHeight, blockHeightAfter)
}
