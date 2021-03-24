package main

import (
	"encoding/json"
	"fmt"
	"github.com/ontio/ontology-crypto/keypair"
	ontology_go_sdk "github.com/ontio/ontology-go-sdk"
	"github.com/ontio/ontology/common/password"
	"github.com/ontio/ontology/smartcontract/service/native/global_params"
	"io/ioutil"
	"os"
	"strings"
	"time"
)

func main() {
	sdk := ontology_go_sdk.NewOntologySdk()
	sdk.NewRpcClient().SetAddress("http://dappnode2.ont.io:20336")

	gasPrice := uint64(2500)
	defGasLimit := uint64(20000000)
	args := os.Args
	if len(args) <= 2 {
		fmt.Println("please input: ", "configFile pre check   0:sendTx, 1:preTx, 0:no-check-address,1:check address")
		return
	}

	configFile := os.Args[1]
	gasLimit := defGasLimit
	if len(args) != 4 {
		fmt.Println("please input: ", "configFile pre check   0:sendTx, 1:preTx, 0:no-check-address,1:check address")
		return
	}
	var pre bool
	preStr := os.Args[2]
	if preStr != "0" {
		pre = true
	}
	var isCheckAddr bool
	checkAddr := os.Args[3]
	if checkAddr != "0" {
		isCheckAddr = true
	}

	configMap := getConfig(configFile)
	//sdk.NewRpcClient().SetAddress("http://polaris2.ont.io:20336")

	walletFileArr := getStringArr(configMap, "wallets")
	destroyedContract := getStringArr(configMap, "blocksc")

	var accArr []*ontology_go_sdk.Account
	var pubKey []keypair.PublicKey
	for _, f := range walletFileArr {
		wa, err := sdk.OpenWallet(f)
		if err != nil {
			fmt.Println(err)
			return
		}
		passwd, err := password.GetAccountPassword()
		if err != nil {
			fmt.Printf("input password error: %s\n", err)
			return
		}
		acc, err := wa.GetAccountByIndex(1, passwd)
		if err != nil {
			fmt.Println(err)
			return
		}
		accArr = append(accArr, acc)
		pubKey = append(pubKey, acc.PublicKey)
	}

	multiAddr, err := sdk.GetMultiAddr(pubKey, 5)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("multiAddr:", multiAddr)

	//检查地址
	if isCheckAddr {
		fmt.Println("start check contract address, it needs a few minutes")
		checkContractAddr(destroyedContract, sdk)
		fmt.Println("check contract address success")
	}

	tx, err := sdk.Native.GlobalParams.NewAddDestroyedContractTransaction(gasPrice, gasLimit, global_params.ADD_DESTROYED_CONTRACT, destroyedContract)
	if err != nil {
		fmt.Println("NewAddDestroyedContractTransaction failed:", err)
		return
	}
	for _, acc := range accArr {
		err = sdk.MultiSignToTransaction(tx, 5, pubKey, acc)
		if err != nil {
			fmt.Println("sign tx failed:", err)
			return
		}
	}
	if pre {
		fmt.Println("*** this is preExcute ***")
		res, err := sdk.PreExecTransaction(tx)
		if err != nil {
			fmt.Println("PreExecTransaction failed:", err)
			return
		}
		fmt.Println("res.State:", res.State)
		fmt.Println("res.Result:", res.Result)
	} else {
		txhash, err := sdk.SendTransaction(tx)
		if err != nil {
			fmt.Println(err)
			return
		}
		fmt.Println("AddDestroyedContract,txHash:", txhash.ToHexString())
		sdk.WaitForGenerateBlock(40*time.Second, 1)
		evt, err := sdk.GetSmartContractEvent(txhash.ToHexString())
		if err != nil {
			fmt.Println(err)
			return
		}
		fmt.Println("AddDestroyedContract, evt:", evt)
	}
}

func checkContractAddr(conAddr []string, sdk *ontology_go_sdk.OntologySdk) {
	finish := 0
	for _, addr := range conAddr {
		_, err := sdk.GetSmartContract(addr)
		finish++
		if finish%20 == 0 {
			fmt.Println("has checked contract number:", finish)
		}
		if err != nil && strings.Contains(err.Error(), "UNKNOWN CONTRACT") {
			continue
		}
		panic("unexpected contract address:" + addr)
	}
}

func getStringArr(args map[string]interface{}, key string) []string {
	res, ok := args[key].([]interface{})
	if !ok {
		panic("getWalletFileArr failed")
	}
	var r []string
	for _, v := range res {
		vStr, ok := v.(string)
		if !ok {
			panic("v.(string) failed")
		}
		r = append(r, vStr)
	}
	return r
}

func getConfig(configFile string) map[string]interface{} {
	bs, err := ioutil.ReadFile(configFile)
	if err != nil {
		fmt.Println(err)
		panic(err)
	}
	configMap := make(map[string]interface{})
	err = json.Unmarshal(bs, &configMap)
	if err != nil {
		fmt.Println(err)
		panic(err)
	}
	return configMap
}
