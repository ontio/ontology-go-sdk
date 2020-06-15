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

package ontology_go_sdk

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"
)

type RelationshipCredential []*Relationship

type Relationship struct {
	Id     string `json:"id"`
	Name   string `json:"name"`
	Spouse string `json:"spouse"`
}

func TestClaim(t *testing.T) {
	Init()

	testOntSdk.SetClaimContractAddress("52df370680de17bc5d4262c446f102a0ee0d6312")
	issuer, err := testWallet.NewDefaultSettingIdentity(testPasswd)
	if err != nil {
		t.Errorf("TestClaim NewDefaultSettingIdentity error:%s", err)
		return
	}
	holder, err := testWallet.NewDefaultSettingIdentity(testPasswd)
	if err != nil {
		t.Errorf("TestClaim NewDefaultSettingIdentity error:%s", err)
		return
	}

	_, err = testOntSdk.Native.OntId.RegIDWithPublicKey(testGasPrice, testGasLimit, testDefAcc, issuer.ID, testDefAcc)
	if err != nil {
		t.Errorf("TestClaim RegIDWithPublicKey error:%s", err)
		return
	}
	_, err = testOntSdk.Native.OntId.RegIDWithPublicKey(testGasPrice, testGasLimit, testDefAcc, holder.ID, testDefAcc)
	if err != nil {
		t.Errorf("TestClaim RegIDWithPublicKey error:%s", err)
		return
	}
	testOntSdk.WaitForGenerateBlock(30 * time.Second)

	credentialSubject := RelationshipCredential(
		[]*Relationship{{"did:example:ebfeb1f712ebc6f1c276e12ec21", "Jayden Doe", "did:example:c276e12ec21ebfeb1f712ebc6f1"},
			{"did:example:c276e12ec21ebfeb1f712ebc6f1", "Morgan Doe", "did:example:ebfeb1f712ebc6f1c276e12ec21"}},
	)
	//var credentialSubject2 interface{}
	request, err := testOntSdk.Claim.GenSignReq(credentialSubject, holder.ID, testDefAcc)
	if err != nil {
		t.Errorf("TestClaim testOntSdk.Claim.GenSignReq error:%s", err)
		return
	}

	err = testOntSdk.Claim.VerifySignReq(request)
	if err != nil {
		t.Errorf("TestClaim testOntSdk.Claim.VerifySignReq error:%s", err)
		return
	}

	contexts := []string{"context1", "context2"}
	types := []string{"RelationshipCredential"}
	expirationDate := time.Now().Unix() + 300
	claim, index, err := testOntSdk.Claim.CreateClaim(contexts, types, credentialSubject, issuer.ID, expirationDate, testDefAcc)
	if err != nil {
		t.Errorf("TestClaim testOntSdk.Claim.CreateClaim error:%s", err)
		return
	}
	claimJson, err := json.Marshal(claim)
	if err != nil {
		t.Errorf("TestClaim json.Marshal claim error:%s", err)
		return
	}
	fmt.Println("claim is: ", string(claimJson))

	txHash, err := testOntSdk.Claim.CommitClaim(500, 20000, claim.Id, issuer.ID, holder.ID, index, testDefAcc, testDefAcc)
	if err != nil {
		t.Errorf("TestClaim testOntSdk.Claim.CommitClaim error:%s", err)
		return
	}
	fmt.Println("txHash is: ", txHash.ToHexString())
	testOntSdk.WaitForGenerateBlock(30 * time.Second)

	err = testOntSdk.Claim.VerifyCredibleOntId([]string{issuer.ID}, claim)
	if err != nil {
		t.Errorf("TestClaim testOntSdk.Claim.VerifyCredibleOntId error:%s", err)
		return
	}
	err = testOntSdk.Claim.VerifyNotExpired(claim)
	if err != nil {
		t.Errorf("TestClaim testOntSdk.Claim.VerifyNotExpired error:%s", err)
		return
	}
	err = testOntSdk.Claim.VerifyIssuerSignature(claim)
	if err != nil {
		t.Errorf("TestClaim testOntSdk.Claim.VerifyIssuerSignature error:%s", err)
		return
	}
	err = testOntSdk.Claim.VerifyStatus(claim)
	if err != nil {
		t.Errorf("TestClaim testOntSdk.Claim.VerifyStatus error:%s", err)
		return
	}

	presentation, err := testOntSdk.Claim.CreatePresentation([]*VerifiableCredential{claim}, contexts, types, holder.ID, []*Account{testDefAcc})
	if err != nil {
		t.Errorf("TestClaim testOntSdk.Claim.CreatePresentation error:%s", err)
		return
	}
	presentationJson, err := json.Marshal(presentation)
	if err != nil {
		t.Errorf("TestClaim json.Marshal presentation error:%s", err)
		return
	}
	fmt.Println("presentation is: ", string(presentationJson))

	err = testOntSdk.Claim.VerifyPresentation(presentation, []string{issuer.ID})
	if err != nil {
		t.Errorf("TestClaim json.Marshal presentation error:%s", err)
		return
	}
}
