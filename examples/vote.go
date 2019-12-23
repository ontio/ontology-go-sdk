package main

import (
	"fmt"
	"github.com/ontio/ontology-go-sdk"
	"github.com/ontio/ontology/common"
	"io/ioutil"
	"os"
	"time"
)

func main() {
	sdk := ontology_go_sdk.NewOntologySdk()
	sdk.NewRpcClient().SetAddress("http://polaris1.ont.io:20336")

	wallet, err := sdk.OpenWallet("./wallet.dat")
	if err != nil {
		fmt.Println("OpenWallet error:", err)
		return
	}
	acc1, err := wallet.GetAccountByAddress("AbtTQJYKfQxq4UdygDsbLVjE8uRrJ2H3tP", []byte("111111"))
	if err != nil {
		fmt.Printf("OpenWallet error: %s", err)
		return
	}
	acc2, err := wallet.GetAccountByAddress("Ac9JHT6gFh6zxpfv4Q7ZPLD4xLhzcpRTWt", []byte("111111"))
	if err != nil {
		fmt.Printf("OpenWallet error: %s", err)
		return
	}

	f, _ := os.Open("VoteContract.avm")
	code, _ := ioutil.ReadAll(f)
	sdk.NewRpcClient().SetAddress("http://polaris1.ont.io:20336")
	contractAddr := common.AddressFromVmCode(code)
	deployCode , err := sdk.GetSmartContract(contractAddr.ToHexString())
	if err != nil {
		return
	}
	if deployCode == nil {
		hash, err := sdk.NeoVM.DeployNeoVMSmartContract(500, 300000, acc1, true, common.ToHexString(code),
			"name", "version", "author", "email", "desc")
		if err != nil {
			fmt.Printf("DeployNeoVMSmartContract error: %s", err)
			return
		}

		time.Sleep(time.Duration(6) * time.Second)
		event, err := sdk.GetSmartContractEvent(hash.ToHexString())
		if err != nil {
			fmt.Printf("GetSmartContractEvent error: %s", err)
			return
		}
		fmt.Println("deploy event:", event)
	}

	vote := &Vote{
		Sdk:          sdk,
		ContractAddr: contractAddr,
		Acc1:         acc1,
		Acc2:         acc2,
	}
	vote.invoke("createTopic", []interface{}{"1111"})
	//vote.invoke("setVoterForTopic", []interface{}{acc1.Address, acc2.Address})
	//vote.preInvoke("listTopics", []interface{}{})
	//vote.preInvoke("getTopic", []interface{}{vote.TopicHash})
	//vote.preInvoke("listTopics", []interface{}{})
	//vote.preInvoke("getVoters", []interface{}{vote.TopicHash})
	//
	//vote.preInvoke("voteTopic", []interface{}{vote.TopicHash, acc1.Address})
	//vote.preInvoke("getTopicStatus", []interface{}{vote.TopicHash})
}

type Vote struct {
	Sdk          *ontology_go_sdk.OntologySdk
	ContractAddr common.Address
	Acc1         *ontology_go_sdk.Account
	Acc2         *ontology_go_sdk.Account
	TopicHash    []byte
}

func (v *Vote) invoke(method string, args []interface{}) {
	hash, err := v.Sdk.NeoVM.InvokeNeoVMContract(500, 2000000, v.Acc1, v.Acc1, v.ContractAddr,
		[]interface{}{method, args})
	if err != nil {
		fmt.Printf("InvokeNeoVMContract error: %s\n", err)
		return
	}
	time.Sleep(time.Duration(6) * time.Second)
	event, err := v.Sdk.GetSmartContractEvent(hash.ToHexString())
	if err != nil {
		fmt.Printf("GetSmartContractEvent error: %s", err)
		return
	}
	fmt.Println("GetSmartContractEvent event:", event)
	if method == "createTopic" {
		for _, notify := range event.Notify {
			addr, _ := common.AddressFromHexString(notify.ContractAddress)
			if addr == v.ContractAddr {
				temp, _ := notify.States.([]interface{})
				t := temp[1].(string)
				tbs, _ := common.HexToBytes(t)
				v.TopicHash = tbs
			}
		}
	}
}

func (v *Vote) preInvoke(method string, args []interface{}) {
	res, err := v.Sdk.NeoVM.PreExecInvokeNeoVMContract(v.ContractAddr,
		[]interface{}{method, args})
	if err != nil {
		fmt.Printf("InvokeNeoVMContract error: %s\n", err)
		return
	}
	fmt.Println("PreExecInvokeNeoVMContract event:", res)
}
