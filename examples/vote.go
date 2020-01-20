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
package main

import (
	"fmt"
	"github.com/ontio/ontology-go-sdk"
	"github.com/ontio/ontology/cmd"
	common2 "github.com/ontio/ontology/cmd/common"
	"github.com/ontio/ontology/cmd/utils"
	"github.com/ontio/ontology/common"
	"github.com/urfave/cli"
	"os"
	"time"
)

var GasPrice = uint64(500)

func main() {
	if err := setupAPP().Run(os.Args); err != nil {
		cmd.PrintErrorMsg(err.Error())
		os.Exit(1)
	}
}

func setupAPP() *cli.App {
	app := cli.NewApp()
	app.Usage = "Ontology CLI"
	app.Action = main2
	app.Flags = []cli.Flag{
		utils.WalletFileFlag,
	}

	return app
}

func main2(ctx *cli.Context) {

	acc, err := common2.GetAccount(ctx)
	if err != nil {
		fmt.Println("GetAccount err:", err)
		return
	}
	acc1 := &ontology_go_sdk.Account{
		PrivateKey: acc.PrivateKey,
		PublicKey:  acc.PublicKey,
		Address:    acc.Address,
		SigScheme:  acc.SigScheme,
	}
	sdk := ontology_go_sdk.NewOntologySdk()
	sdk.NewRpcClient().SetAddress("http://dappnode1.ont.io:20336")

	//acc1, err := wallet.GetAccountByAddress("AbtTQJYKfQxq4UdygDsbLVjE8uRrJ2H3tP", pwd)
	//if err != nil {
	//	fmt.Printf("OpenWallet error: %s", err)
	//	return
	//}
	address := []string{"AGgCp8dKedjJXaWDoU4qfnSAU6pgLKhxVx",
		"AUis5bkN19QyRBZuV5tayZc1onSX17pWEi",
		"AbPsjYENUywQDDNdMq8iCGHXLduP1zbqaZ",
		"AJ6exTNyr8joCkBEbz6DpHbe357EoBX1Tf",
		"AUEAGG1pWTg2nAMsoR4x6EvSN2wb2wdZHx",
		"AYgiXzs4b7XmaQjNoo6ANuFJ5zHDebgPdq",
		"AXtswyDXUgkpUobpyc9cj8cTTAtAdMbTTy",
		"ARXKEj5r61cWm1X7DLZttDJo3D5Zhwdexc",
		"AGUekTnhucrQShdATUFhZqFqiPdC65nRxv",
		"AbZuVX9M2F4cw6myDFVP9shAFKPm8xBY9J",
		"AV59sm9kRGB4EYRKCMYXXsiCPKzbAFMcpA",
		"AGns9etVHUknEgZ6yUhnHSZm6G6AxKXkPx",
		"AcdH5iCT5DSxUio29YMykT8eakgbjYeWBW",
		"AVaQJM27YxLkD5JAd1n4wGnxMx2Ey1h9cQ",
		"AHnRpJ8Hnk9eAdDsW1gMAwTK88pvtZEGfg",
		"APP42849YXfRtDp5Y4bTVbt1g5vhajAAya",
		"Aa1MF3pTq4CaE3HK4umgZL3WxLh3A1CiBH",
		"ATTzSUQm5MgXQCLfrbWBv9hSBLcZX75giR",
		"AWWChRewNcQ5nZuh8LzF8ksqPaCW8EXPBU",
		"AevYU9HK7B4iryyx6Av5iEVczBkfmM3cXy",
		"AW4ytrVJX2h6W2jxKCf5Ws2bh1DUXAK2qq",
		"Ac8P8376ozoQ5H2Srcm32n5yb8kLoixRaP",
		"APSFBEbQzMUjuCtSVwHcRjiqCrDe56jAHJ",
		"AXwfq4jnhvByDmvuFhFzHSSdKJ3GQTwZ8Z",
		"ANumnYcRtbT1XxCw1hs9WGjJaDURMxiuQ9",
		"AWGrHN1DUAo6Ao3yTHu4tUHZonPNAy9ZmU",
		"ALZ3dhx4K74TAiLkprBRPWNe4LppW5ff6P",
		"ASPPqj8yCcCV2sWHQZwsYfWZS2FMfd3PF7",
		"ALfbQ4yv4Pho31DA1EoeacMj6VJhyxDHqu",
		"AKkcxjHGXnF68FYNP5UQ5Hkv4j3HBsdmP5",
		"AGgP7kWDSxzbRHdeDwULwYUV7qVuKWBoTr",
		"AGqzuKoEeDfMHPEBPJVs2h2fapxDGoGtK1",
		"AGEdeZu965DFFFwsAWcThgL6uduJf4U7ci",
		"AXMKzXMc9nKpZJYecPe5NBLJraZwJ37zbg",
		"AModfYVLuvvaacsexSBAvegnykog5yH2Ji",
		"ALaDrS5ZwMKZgTS3a8okgDDz84k3ttfP4x",
		"ATGDCxCUEzGdX2mpLriT3hBUK7VW3dX1FT",
		"AXNxyP2HEKW7GoSqYfeqcYfCSE7XaaVVu4",
		"AY65tbb1bzDJ4fbcqPCExMyMEq2BRNb9fu",
		"AMJskicSD18QzVYcx5o4F6d67dbG4kKW7v",
		"AZ3TqZAEhUELfNHrjrmXShbVzKJv64x12w",
		"AKshHCFGWHMftXELBmogxrjrDMW61xgph9",
		"ASNRUBi1X56kW55zRv7jFPQsE6SngBJfrs",
		"ANRRE8xKwKzuaCeAjP6eZYDnVi7n2x6byE",
		"AUy6TaM9wxTqo9T7FiaYMnDeVExhjsR1Pq",
		"AFsfeivZ1iTbL1sqY8UkTZ8kqygwGerDNj",
		"AJiEBNzr4NeAyaQx6qn1jgNkLFCgxtTt5U",
		"AbGDhXXyjHLBc53BDR8jrRZLAL1BteL7VA",
		"AX9MxQSbQPKKA4cP9VzTwE8o6MXC3pC9Nw",
		"AJEAVCJpa7JmpDZsJ9vPA1r9fPZAvjec8D"}
	addr := make([]common.Address, 0)
	for _, item := range address {
		add, _ := common.AddressFromBase58(item)
		addr = append(addr, add)
	}
	contractAddr, _ := common.AddressFromHexString("c0df752ca786a99755b2e8950060ade9fa3d4e1b")

	vote := &Vote{
		Sdk:          sdk,
		ContractAddr: contractAddr,
		Acc1:         acc1,
	}

	fmt.Println("")
	fmt.Println("******init****")
	vote.invoke("init", []interface{}{})

	fmt.Println("")
	fmt.Println("******setAdmin****")
	vote.invoke("setAdmin", []interface{}{addr})

}

type Vote struct {
	Sdk          *ontology_go_sdk.OntologySdk
	ContractAddr common.Address
	Acc1         *ontology_go_sdk.Account
	Acc2         *ontology_go_sdk.Account
	TopicHash    []byte
}

func (v *Vote) invoke(method string, args []interface{}) {
	hash, err := v.Sdk.NeoVM.InvokeNeoVMContract(GasPrice, 2000000, v.Acc1, v.Acc1, v.ContractAddr,
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
	fmt.Println("Event notify:", event)
	if method == "createTopic" {
		for _, notify := range event.Notify {
			addr, _ := common.AddressFromHexString(notify.ContractAddress)
			if addr == v.ContractAddr {
				temp, _ := notify.States.([]interface{})
				t := temp[1].(string)
				tbs, _ := common.HexToBytes(t)
				v.TopicHash = tbs
				fmt.Println("Event notify:", temp)
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
	if method == "getTopicStatus" {
		r, _ := res.Result.ToString()
		fmt.Println("PreExecInvokeNeoVMContract result:", r)
	} else {
		fmt.Println("PreExecInvokeNeoVMContract result:", res.Result)
	}
}
