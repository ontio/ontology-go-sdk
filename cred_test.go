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
	"github.com/ontio/ontology/common"
	"testing"
	"time"
)

type RelationshipCredential []*Relationship

type Relationship struct {
	Id     string `json:"id"`
	Name   string `json:"name"`
	Spouse string `json:"spouse"`
}

func TestCreditial(t *testing.T) {
	Init()

	testOntSdk.SetCredContractAddress("52df370680de17bc5d4262c446f102a0ee0d6312")
	issuer, err := testWallet.NewDefaultSettingIdentity(testPasswd)
	if err != nil {
		t.Errorf("TestCreditial NewDefaultSettingIdentity error:%s", err)
		return
	}
	holder, err := testWallet.NewDefaultSettingIdentity(testPasswd)
	if err != nil {
		t.Errorf("TestCreditial NewDefaultSettingIdentity error:%s", err)
		return
	}

	_, err = testOntSdk.Native.OntId.RegIDWithPublicKey(testGasPrice, testGasLimit, testDefAcc, issuer.ID, testDefAcc)
	if err != nil {
		t.Errorf("TestCreditial RegIDWithPublicKey error:%s", err)
		return
	}
	_, err = testOntSdk.Native.OntId.RegIDWithPublicKey(testGasPrice, testGasLimit, testDefAcc, holder.ID, testDefAcc)
	if err != nil {
		t.Errorf("TestCreditial RegIDWithPublicKey error:%s", err)
		return
	}
	testOntSdk.WaitForGenerateBlock(30 * time.Second)

	credentialSubject := RelationshipCredential(
		[]*Relationship{{"did:example:ebfeb1f712ebc6f1c276e12ec21", "Jayden Doe", "did:example:c276e12ec21ebfeb1f712ebc6f1"},
			{"did:example:c276e12ec21ebfeb1f712ebc6f1", "Morgan Doe", "did:example:ebfeb1f712ebc6f1c276e12ec21"}},
	)
	//var credentialSubject2 interface{}
	request, err := testOntSdk.Credential.GenSignReq(credentialSubject, holder.ID, testDefAcc)
	if err != nil {
		t.Errorf("TestCreditial testOntSdk.Credential.GenSignReq error:%s", err)
		return
	}

	err = testOntSdk.Credential.VerifySignReq(request)
	if err != nil {
		t.Errorf("TestCreditial testOntSdk.Credential.VerifySignReq error:%s", err)
		return
	}

	contexts := []string{"context1", "context2"}
	types := []string{"RelationshipCredential"}
	expirationDate := time.Now().Unix() + 300
	credential, err := testOntSdk.Credential.CreateCredential(contexts, types, credentialSubject, issuer.ID, expirationDate,
		"", "", testDefAcc)
	if err != nil {
		t.Errorf("TestCreditial testOntSdk.Credential.CreateCredential error:%s", err)
		return
	}
	credentialJson, err := json.Marshal(credential)
	if err != nil {
		t.Errorf("TestCreditial json.Marshal credential error:%s", err)
		return
	}
	fmt.Println("credential is: ", string(credentialJson))

	contractAddress, err := common.AddressFromHexString(credential.CredentialStatus.Id)
	if err != nil {
		t.Errorf("TestCreditial common.AddressFromHexString:%s", err)
		return
	}
	txHash, err := testOntSdk.Credential.CommitCredential(contractAddress, 500, 20000, credential.Id, issuer.ID, holder.ID, testDefAcc, testDefAcc)
	if err != nil {
		t.Errorf("TestCreditial testOntSdk.Credential.CommitCredential error:%s", err)
		return
	}
	fmt.Println("txHash 1 is: ", txHash.ToHexString())
	testOntSdk.WaitForGenerateBlock(30 * time.Second)

	err = testOntSdk.Credential.VerifyCredibleOntId([]string{issuer.ID}, credential)
	if err != nil {
		t.Errorf("TestCreditial testOntSdk.Credential.VerifyCredibleOntId error:%s", err)
		return
	}
	err = testOntSdk.Credential.VerifyDate(credential)
	if err != nil {
		t.Errorf("TestCreditial testOntSdk.Credential.VerifyDate error:%s", err)
		return
	}
	err = testOntSdk.Credential.VerifyIssuerSignature(credential)
	if err != nil {
		t.Errorf("TestCreditial testOntSdk.Credential.VerifyIssuerSignature error:%s", err)
		return
	}
	err = testOntSdk.Credential.VerifyStatus(credential)
	if err != nil {
		t.Errorf("TestCreditial testOntSdk.Credential.VerifyStatus error:%s", err)
		return
	}

	presentation, err := testOntSdk.Credential.CreatePresentation([]*VerifiableCredential{credential}, contexts, types, holder.ID,
		[]string{issuer.ID}, []string{""}, []interface{}{""}, []*Account{testDefAcc})
	if err != nil {
		t.Errorf("TestCreditial testOntSdk.Credential.CreatePresentation error:%s", err)
		return
	}
	presentationJson, err := json.Marshal(presentation)
	if err != nil {
		t.Errorf("TestCreditial json.Marshal presentation error:%s", err)
		return
	}
	fmt.Println("presentation is: ", string(presentationJson))

	for i := range presentation.Proof {
		_, err = testOntSdk.Credential.VerifyPresentationProof(presentation, i)
		if err != nil {
			t.Errorf("TestCreditial testOntSdk.Credential.VerifyPresentationProof error:%s", err)
			return
		}
	}

	txHash, err = testOntSdk.Credential.RevokeCredentialByHolder(500, 20000, credential, holder.ID, testDefAcc, testDefAcc)
	if err != nil {
		t.Errorf("TestCreditial testOntSdk.Credential.RevokeCredentialByHolder error:%s", err)
		return
	}
	fmt.Println("txHash 2 is: ", txHash.ToHexString())
	testOntSdk.WaitForGenerateBlock(30 * time.Second)

	txHash, err = testOntSdk.Credential.RemoveCredential(500, 20000, credential, holder.ID, testDefAcc, testDefAcc)
	if err != nil {
		t.Errorf("TestCreditial testOntSdk.Credential.RevokeCredentialByHolder error:%s", err)
		return
	}
	fmt.Println("txHash 3 is: ", txHash.ToHexString())
}
