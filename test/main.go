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
	ontology_go_sdk "github.com/ontio/ontology-go-sdk"
	"github.com/ontio/ontology/core/payload"
)

func main2() {
	testOntSdk := ontology_go_sdk.NewOntologySdk()
	testOntSdk.NewRpcClient().SetAddress("http://dappnode1.ont.io:20336")
	for i := uint32(4513925); i > 100000; i++ {
		block, err := testOntSdk.GetBlockByHeight(i)
		if err != nil {
			fmt.Println("error: ", err)
			return
		}
		for _, tx := range block.Transactions {
			invokeCode, ok := tx.Payload.(*payload.InvokeCode)
			if ok {
				res, err := ontology_go_sdk.ParsePayload(invokeCode.Code)
				if err != nil {
					//fmt.Printf("error: %s, height:%d\n", err, i)
					continue
				}
				fmt.Println("res:", res)
				fmt.Printf("height: %d\n", i)
			}
		}
	}
}
