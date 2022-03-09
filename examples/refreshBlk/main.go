package main

import (
	"fmt"
	ontology_go_sdk "github.com/ontio/ontology-go-sdk"
	"time"
)

func main() {
	sdk := ontology_go_sdk.NewOntologySdk()
	testUrl := "http://polaris3.ont.io:20336"
	sdk.NewRpcClient().SetAddress(testUrl)

	wa, err := sdk.OpenWallet("../wallet.dat")
	if err != nil {
		panic(err)
	}
	acct, err := wa.GetAccountByAddress("ASs69u7L9ddXbiqFvNK7jswZAWaSU55vVU", []byte("111111"))
	if err != nil {
		panic(err)
	}
	fmt.Println(acct.Address.ToBase58())
	endHeight := uint32(16595065)
	for {
		blkH, err := sdk.GetCurrentBlockHeight()
		if err != nil || blkH == 0 {
			continue
		}
		if blkH > endHeight {
			return
		}
		sdk.Native.Ong.Transfer(2500, 20000, acct, acct, acct.Address, 0)
		time.Sleep(time.Second * 2)
	}
}
