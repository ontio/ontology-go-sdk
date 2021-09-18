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
package oep4

import (
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/ontio/ontology-crypto/keypair"
	ontology_go_sdk "github.com/ontio/ontology-go-sdk"
	"github.com/ontio/ontology-go-sdk/utils"
	"github.com/ontio/ontology/common"
	"github.com/ontio/ontology/core/types"
)

const scriptHash = "5e0aebb3dcc7af619e019a8f2195151d4d59644d"

func TestOep4(t *testing.T) {
	contractAddr, err := utils.AddressFromHexString(scriptHash)
	if err != nil {
		t.Fatal(err)
	}
	ontSdk := ontology_go_sdk.NewOntologySdk()
	ontSdk.NewRpcClient().SetAddress("http://polaris2.ont.io:20336")
	oep4 := NewOep4(contractAddr, ontSdk)
	name, err := oep4.Name()
	if err != nil {
		t.Fatal(err)
	}
	symbol, err := oep4.Symbol()
	if err != nil {
		t.Fatal(err)
	}
	decimals, err := oep4.Decimals()
	if err != nil {
		t.Fatal(err)
	}
	totalSupply, err := oep4.TotalSupply()
	if err != nil {
		t.Fatal(err)
	}

	wallet, err := ontSdk.OpenWallet("../../wallet.json")
	if err != nil {
		fmt.Println("OpenWallet error:", err)
		return
		t.Fatal(err)
	}
	if wallet.GetAccountCount() < 2 {
		t.Fatal("account not enough")
	}
	acc, err := wallet.GetDefaultAccount([]byte("passwordtest"))
	if err != nil {
		t.Fatal(err)
	}
	balance, err := oep4.BalanceOf(acc.Address)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("name %s, symbol %s, decimals %d, totalSupply %d, balanceOf %s is %d",
		name, symbol, decimals, totalSupply, acc.Address.ToBase58(), balance)

	anotherAccount, err := wallet.GetAccountByIndex(2, []byte("passwordtest"))
	if err != nil {
		t.Fatal(err)
	}
	m := 2
	multiSignAddr, err := types.AddressFromMultiPubKeys([]keypair.PublicKey{acc.PublicKey, anotherAccount.PublicKey}, m)
	if err != nil {
		t.Fatal(err)
	}
	amount := big.NewInt(1000)
	gasPrice := uint64(2500)
	gasLimit := uint64(500000)
	transferTx, err := oep4.Transfer(acc, multiSignAddr, amount, nil, gasPrice, gasLimit)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("transferTx %s: from %s to multi-sign addr %s, amount %d", transferTx.ToHexString(),
		acc.Address.ToBase58(), multiSignAddr.ToBase58(), amount)
	accounts := []*ontology_go_sdk.Account{acc, anotherAccount}
	transferMultiSignTx, err := oep4.MultiSignTransfer(accounts, m, acc.Address, amount, gasPrice, gasLimit)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("transferMultiSignTx %s: from %s to multi-sign addr %s, amount %d", transferMultiSignTx.ToHexString(),
		multiSignAddr.ToBase58(), acc.Address.ToBase58(), amount)
	approveTx, err := oep4.Approve(acc, multiSignAddr, amount, nil, gasPrice, gasLimit)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("approveTx %s: owner %s approve to multi-sign spender addr %s, amount %d", approveTx.ToHexString(),
		acc.Address.ToBase58(), multiSignAddr.ToBase58(), amount)
	multiSignTransferFromTx, err := oep4.MultiSignTransferFrom(accounts, m, acc.Address, multiSignAddr, amount,
		gasPrice, gasLimit)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("multiSignTransferFromTx %s: owner %s, multi-sign spender addr %s, to %s, amount %d",
		multiSignTransferFromTx.ToHexString(), acc.Address.ToBase58(), multiSignAddr.ToBase58(), multiSignAddr.ToBase58(),
		amount)
	multiSignApproveTx, err := oep4.MultiSignApprove(accounts, m, acc.Address, amount, gasPrice, gasLimit)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("multiSignApproveTx %s: multi-sign owner %s approve to spender addr %s, amount %d",
		multiSignApproveTx.ToHexString(), multiSignAddr.ToBase58(), acc.Address.ToBase58(), amount)
	transferFromTx, err := oep4.TransferFrom(acc, multiSignAddr, acc.Address, amount, nil, gasPrice, gasLimit)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("transferFromTx %s: multi-sign owner %s, spender addr %s, to %s, amount %d",
		transferFromTx.ToHexString(), multiSignAddr.ToBase58(), acc.Address.ToBase58(), acc.Address.ToBase58(), amount)
	_, _ = ontSdk.WaitForGenerateBlock(30 * time.Second)

	eventsFromTx, err := oep4.FetchTxTransferEvent(transferTx.ToHexString())
	if err != nil {
		t.Fatal(err)
	}
	for _, evt := range eventsFromTx {
		t.Logf("tx %s transfer event: %s", transferTx.ToHexString(), evt.String())
	}

	height := uint32(1791727)
	eventsFromBlock, err := oep4.FetchBlockTransferEvent(height)
	if err != nil {
		t.Fatal(err)
	}
	for _, evt := range eventsFromBlock {
		t.Logf("block %d transfer event: %s", height, evt.String())
	}
}

func TestOep4_FetchTxTransferEvent(t *testing.T) {
	contractAddr, err := utils.AddressFromHexString(scriptHash)
	if err != nil {
		t.Fatal(err)
	}
	//from address
	bs, _ := common.HexToBytes("83c12e967885ba0a1285a0c628acbfb1185af8bc")
	addr, _ := common.AddressParseFromBytes(bs)
	fmt.Println(addr.ToBase58())
	ontSdk := ontology_go_sdk.NewOntologySdk()
	ontSdk.NewRpcClient().SetAddress("http://polaris2.ont.io:20336")
	oep4 := NewOep4(contractAddr, ontSdk)
	res, _ := oep4.FetchTxTransferEvent("8074fabad95400c6705478593f2b2fce865aa356c166e63214d8a9af036ee739")
	fmt.Println(res)
}
