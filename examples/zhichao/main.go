package main

import (
	"fmt"
	ontology_go_sdk "github.com/ontio/ontology-go-sdk"
	"github.com/ontio/ontology/common/password"
	"os"
	"strconv"
	"strings"
	"time"
)

func main() {
	gasPrice := uint64(2500)
	defGasLimit := uint64(20000000)
	args := os.Args
	if len(args) <= 3 {
		fmt.Println("please input: ", "walletFile, address, destroyedContract, [gaslimit]")
		return
	}
	walletFile := os.Args[1]
	address := os.Args[2]
	destroyedContractStr := os.Args[3]
	gasLimit := defGasLimit
	if len(os.Args) > 4 {
		gasLimitStr := os.Args[4]
		temp, err := strconv.ParseUint(gasLimitStr, 10, 64)
		if err != nil {
			fmt.Println("gasLimit error:", err)
			return
		}
		gasLimit = temp
	}
	destroyedContract := strings.Split(destroyedContractStr, ",")

	sdk := ontology_go_sdk.NewOntologySdk()
	sdk.NewRpcClient().SetAddress("http://dappnode2.ont.io:20336")
	sdk.NewRpcClient().SetAddress("http://127.0.0.1:20336")

	wa, err := sdk.OpenWallet(walletFile)
	if err != nil {
		fmt.Println(err)
		return
	}
	passwd, err := password.GetAccountPassword()
	if err != nil {
		fmt.Printf("input password error: %s\n", err)
		return
	}
	acc, err := wa.GetAccountByAddress(address, passwd)
	if err != nil {
		fmt.Println(err)
		return
	}
	txhash, err := sdk.Native.GlobalParams.AddDestroyedContract(acc, destroyedContract, gasPrice, gasLimit)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("txhash:", txhash.ToHexString())
	sdk.WaitForGenerateBlock(40*time.Second, 1)
	evt, err := sdk.GetSmartContractEvent(txhash.ToHexString())
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("evt:", evt)
}
