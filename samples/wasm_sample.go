package main

import (
	"fmt"
	sdk "github.com/ontio/ontology-go-sdk"

	"time"
	"io/ioutil"
	"github.com/ontio/ontology/common"
	"github.com/ontio/ontology-go-sdk/utils"
	"encoding/binary"
)

func main(){
	fmt.Println("==========================start============================")

	//initialize ontsdk
	ontSdk := sdk.NewOntologySdk()
	//suppose you already start up a local wasm ontology node
	ontSdk.NewRpcClient().SetAddress("http://127.0.0.1:20336")
	//your wallet file
	wallet, err := ontSdk.OpenWallet("./wallet.dat")
	if err != nil{
		fmt.Printf("error in OpenWallet:%s\n",err)
		return
	}

	//modify me
	walletpassword:="<pass word of your wallet>"

	//we get the first account of the wallet by your password
	signer,err := wallet.GetDefaultAccount([]byte(walletpassword))
	if err != nil{
		fmt.Printf("error in GetDefaultAccount:%s\n",err)
		return
	}
	fmt.Printf("===signer address is %s\n",signer.Address.ToBase58())
	//get a compiled wasm file from ont_cpp
	wasmfile := "./OEP4.wasm"

	//set timeout
	timeoutSec := 30 * time.Second
	address1 := "<other address in your wallet>"


	// read wasm file and get the Hex fmt string
	code, err := ioutil.ReadFile(wasmfile)
	if err != nil {
		fmt.Printf("error in ReadFile:%s\n",err)

		return
	}

	codeHash := common.ToHexString(code)

	//===========================================
	gasprice := uint64(0)
	invokegaslimit := uint64(200000)
	deploygaslimit := uint64(200000000)
	// deploy the wasm contract
	fmt.Println("======DeployWasmVMSmartContract ==========")
	txHash, err := ontSdk.WasmVM.DeployWasmVMSmartContract(
		gasprice,
		deploygaslimit,
		signer,
		codeHash,
		"OEP4 wasm",
		"1.0",
		"author",
		"email",
		"desc",
	)
	if err != nil{
		fmt.Printf("error in DeployWasmVMSmartContract:%s\n",err)

		return
	}
	_, err = ontSdk.WaitForGenerateBlock(timeoutSec)
	if err != nil {
		fmt.Printf("error in WaitForGenerateBlock:%s\n",err)

		return
	}
	fmt.Printf("the deploy contract txhash is %s\n",txHash.ToHexString())

	//calculate the contract address from code
	contractAddr, err := utils.GetContractAddress(codeHash)
	if err != nil {
		fmt.Printf("error in GetContractAddress:%s\n",err)

		return
	}
	fmt.Printf("the contractAddr is %s\n",contractAddr.ToBase58())

	fmt.Println("======InvokeWasmVMSmartContract init==========")

	//============================================
	//invoke wasm method
	//we invoke "init" method first
	txHash, err  = ontSdk.WasmVM.InvokeWasmVMSmartContract(
		gasprice,invokegaslimit,signer,contractAddr,"init",[]interface{}{})
	_, err = ontSdk.WaitForGenerateBlock(timeoutSec)
	if err != nil {
		fmt.Printf("error in WaitForGenerateBlock:%s\n",err)
		return
	}
	fmt.Printf("init txhash is :%s\n",txHash.ToHexString())
	//get smartcontract event by txhash
	events, err := ontSdk.GetSmartContractEvent(txHash.ToHexString())
	if err != nil {
		fmt.Printf("error in GetSmartContractEvent:%s\n",err)

		return
	}
	fmt.Printf("event is %v\n", events)
	//State = 0 means transaction failed
	if events.State == 0 {
		fmt.Printf("error in events.State is 0 failed.\n")

		return
	}
	fmt.Printf("events.Notify:%v", events.Notify)
	for _, notify := range events.Notify {
		fmt.Printf("%+v\n", notify)
	}

	//next we test transfer method
	//1.  we get another address from wallet,suppose you have created in the wallet
	account2, err := wallet.GetAccountByAddress(address1,[]byte(walletpassword))
	if err != nil {
		fmt.Printf("error in GetAccountByAddress:%s\n",err)

		return
	}
	fmt.Println("======InvokeWasmVMSmartContract transfer==========")

	//2. we construct a tx transfer 500 token from signer account to account2
	txHash, err  = ontSdk.WasmVM.InvokeWasmVMSmartContract(
		gasprice,invokegaslimit,signer,contractAddr,"transfer",[]interface{}{signer.Address,account2.Address,uint64(500)})
	_, err = ontSdk.WaitForGenerateBlock(timeoutSec)
	if err != nil {
		fmt.Printf("error in WaitForGenerateBlock:%s\n",err)

		return
	}
	//get smartcontract event by txhash
	events, err = ontSdk.GetSmartContractEvent(txHash.ToHexString())
	if err != nil {
		fmt.Printf("error in GetSmartContractEvent:%s\n",err)
		return
	}
	fmt.Printf("event is %v\n", events)
	//State = 0 means transaction failed
	if events.State == 0 {
		fmt.Printf("error in events.State is 0 failed.\n")

		return
	}
	fmt.Printf("events.Notify:%v", events.Notify)
	for _, notify := range events.Notify {
		//you check the notify here
		fmt.Printf("%+v\n", notify)
	}

	//we will query the balance using pre-execuse method
	res,err := ontSdk.WasmVM.PreExecInvokeWasmVMContract(contractAddr, "balanceOf", []interface{}{signer.Address})
	if err != nil {
		fmt.Printf("error in PreExecInvokeWasmVMContract:%s\n",err)

		return
	}
	bs, err := res.Result.ToByteArray()
	if err != nil {
		fmt.Printf("error in ToByteArray:%s\n",err)

		return
	}
	fmt.Printf("balance of %s is %d\n", signer.Address.ToBase58(), binary.LittleEndian.Uint64(bs))

	fmt.Println("==============================end ==========================")
}
