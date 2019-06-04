package main

import (
	"fmt"
	ontology_go_sdk "github.com/ontio/ontology-go-sdk"
	"github.com/ontio/ontology/core/payload"
)

func main() {
	testOntSdk := ontology_go_sdk.NewOntologySdk()
	testOntSdk.NewRpcClient().SetAddress("http://dappnode1.ont.io:20336")
	for i := uint32(0); i < 100000; i++ {
		block, err := testOntSdk.GetBlockByHeight(i)
		if err != nil {
			fmt.Println("error: ", err)
			return
		}
		for _, tx := range block.Transactions {
			invokeCode, ok := tx.Payload.(*payload.InvokeCode)
			if ok {
				res, err := testOntSdk.ParsePayload(invokeCode.Code)
				if err != nil {
					fmt.Printf("error: %s, height:%d\n", err, i)
					continue
				}
				fmt.Printf("res: %x, height: %d\n", res, i)
			}
		}
	}
}
