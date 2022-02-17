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

	"github.com/ontio/ontology-go-sdk/utils"
	"github.com/stretchr/testify/assert"

	"github.com/ontio/ontology/common"
)

type RelationshipCredential []*Relationship

type Relationship struct {
	Id     string `json:"id"`
	Name   string `json:"name"`
	Spouse string `json:"spouse"`
}

func TestCredential(t *testing.T) {
	Init()
	contractAddr, err := utils.GetContractAddress(CredentialCode)
	assert.Nil(t, err)
	err = testOntSdk.SetCredContractAddress(contractAddr.ToHexString())
	assert.Nil(t, err)
	issuer, err := testWallet.NewDefaultSettingIdentity(testPasswd)
	if err != nil {
		t.Errorf("TestCredential NewDefaultSettingIdentity error:%s", err)
		return
	}
	holder, err := testWallet.NewDefaultSettingIdentity(testPasswd)
	if err != nil {
		t.Errorf("TestCredential NewDefaultSettingIdentity error:%s", err)
		return
	}

	_, err = testOntSdk.Native.OntId.RegIDWithPublicKey(testGasPrice, testGasLimit, testDefAcc, issuer.ID, testDefAcc)
	if err != nil {
		t.Errorf("TestCredential RegIDWithPublicKey error:%s", err)
		return
	}
	_, err = testOntSdk.Native.OntId.RegIDWithPublicKey(testGasPrice, testGasLimit, testDefAcc, holder.ID, testDefAcc)
	if err != nil {
		t.Errorf("TestCredential RegIDWithPublicKey error:%s", err)
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
		t.Errorf("TestCredential testOntSdk.Credential.GenSignReq error:%s", err)
		return
	}

	err = testOntSdk.Credential.VerifySignReq(request)
	if err != nil {
		t.Errorf("TestCredential testOntSdk.Credential.VerifySignReq error:%s", err)
		return
	}

	contexts := []string{"context1", "context2"}
	types := []string{"RelationshipCredential"}
	expirationDate := time.Now().UTC().Unix() + 86400
	credential, err := testOntSdk.Credential.CreateCredential(contexts, types, credentialSubject, issuer.ID, expirationDate,
		"", "", testDefAcc)
	if err != nil {
		t.Errorf("TestCredential testOntSdk.Credential.CreateCredential error:%s", err)
		return
	}
	credentialJson, err := json.Marshal(credential)
	if err != nil {
		t.Errorf("TestCredential json.Marshal credential error:%s", err)
		return
	}
	fmt.Println("credential is: ", string(credentialJson))

	contractAddress, err := common.AddressFromHexString(credential.CredentialStatus.Id)
	if err != nil {
		t.Errorf("TestCredential common.AddressFromHexString:%s", err)
		return
	}
	txHash, err := testOntSdk.Credential.CommitCredential(contractAddress, 2500, 20000, credential.Id, issuer.ID, holder.ID, testDefAcc, testDefAcc)
	if err != nil {
		t.Errorf("TestCredential testOntSdk.Credential.CommitCredential error:%s", err)
		return
	}
	fmt.Println("txHash 1 is: ", txHash.ToHexString())
	testOntSdk.WaitForGenerateBlock(30 * time.Second)

	err = testOntSdk.Credential.VerifyCredibleOntId([]string{issuer.ID}, credential)
	if err != nil {
		t.Errorf("TestCredential testOntSdk.Credential.VerifyCredibleOntId error:%s", err)
		return
	}
	err = testOntSdk.Credential.VerifyIssuanceDate(credential)
	if err != nil {
		t.Errorf("TestCredential testOntSdk.Credential.VerifyIssuanceDate error:%s", err)
		return
	}
	err = testOntSdk.Credential.VerifyExpirationDate(credential)
	if err != nil {
		t.Errorf("TestCredential testOntSdk.Credential.VerifyExpirationDate error:%s", err)
		return
	}
	err = testOntSdk.Credential.VerifyIssuerSignature(credential)
	if err != nil {
		t.Errorf("TestCredential testOntSdk.Credential.VerifyIssuerSignature error:%s", err)
		return
	}
	err = testOntSdk.Credential.VerifyStatus(credential)
	if err != nil {
		t.Errorf("TestCredential testOntSdk.Credential.VerifyStatus error:%s", err)
		return
	}

	presentation, err := testOntSdk.Credential.CreatePresentation([]*VerifiableCredential{credential}, contexts, types, holder.ID,
		[]string{issuer.ID}, []string{""}, []interface{}{""}, []*Account{testDefAcc})
	if err != nil {
		t.Errorf("TestCredential testOntSdk.Credential.CreatePresentation error:%s", err)
		return
	}
	presentationJson, err := json.Marshal(presentation)
	if err != nil {
		t.Errorf("TestCredential json.Marshal presentation error:%s", err)
		return
	}
	fmt.Println("presentation is: ", string(presentationJson))

	for i := range presentation.Proof {
		_, err = testOntSdk.Credential.VerifyPresentationProof(presentation, i)
		if err != nil {
			t.Errorf("TestCredential testOntSdk.Credential.VerifyPresentationProof error:%s", err)
			return
		}
	}

	txHash, err = testOntSdk.Credential.RevokeCredentialByHolder(2500, 20000, credential, holder.ID, testDefAcc, testDefAcc)
	if err != nil {
		t.Errorf("TestCredential testOntSdk.Credential.RevokeCredentialByHolder error:%s", err)
		return
	}
	fmt.Println("txHash 2 is: ", txHash.ToHexString())
	testOntSdk.WaitForGenerateBlock(30 * time.Second)

	txHash, err = testOntSdk.Credential.RemoveCredential(2500, 20000, credential, holder.ID, testDefAcc, testDefAcc)
	if err != nil {
		t.Errorf("TestCredential testOntSdk.Credential.RevokeCredentialByHolder error:%s", err)
		return
	}
	fmt.Println("txHash 3 is: ", txHash.ToHexString())
}

//func TestVerifyJSONCred(t *testing.T) {
//	Init()
//
//	credibleOntIds := []string{"did:ont:AJ4C9aTYxTGUhEpaZdPjFSqCqzMCqJDRUd",
//		"did:ont:AVe4zVZzteo6HoLpdBwpKNtDXLjJBzB9fv"}
//	credString := "{\"@context\":[\"https://www.w3.org/2018/credentials/v1\",\"https://ontid.ont.io/credentials/v1\"],\"id\":\"urn:uuid:5375555d-9ea2-4a4b-8318-11c28c9bde48\",\"type\":[\"VerifiableCredential\",\"RelationshipCredential\"],\"issuer\":\"did:ont:AJ4C9aTYxTGUhEpaZdPjFSqCqzMCqJDRUd\",\"issuanceDate\":\"2020-06-29T10:11:36Z\",\"expirationDate\":\"2020-06-30T10:11:36Z\",\"credentialSubject\":[{\"id\":\"did:ont:111111\",\"name\":\"Bob\",\"spouse\":\"Alice\"}],\"credentialStatus\":{\"id\":\"52df370680de17bc5d4262c446f102a0ee0d6312\",\"type\":\"AttestContract\"},\"proof\":{\"type\":\"EcdsaSecp256r1VerificationKey2019\",\"created\":\"2020-06-29T10:11:36Z\",\"proofPurpose\":\"assertionMethod\",\"verificationMethod\":\"did:ont:AJ4C9aTYxTGUhEpaZdPjFSqCqzMCqJDRUd#keys-2\",\"hex\":\"01d899e082ad8644cc01ade2f2eeb9b66443cc518c5d56e5a8ef7a562592a189ef19e2a883eb2d6dd4c4817e8b1841663e56b7cb66aba5dfd2f4f777faeda40bf7\"}}"
//	credential := &VerifiableCredential{}
//	if err := json.Unmarshal([]byte(credString), credential); err != nil {
//		t.Fatal(err)
//	}
//	err := testOntSdk.Credential.VerifyCredibleOntId(credibleOntIds, credential)
//	if err != nil {
//		t.Fatal(err)
//	}
//	err = testOntSdk.Credential.VerifyDate(credential)
//	if err != nil {
//		t.Fatal(err)
//	}
//	err = testOntSdk.Credential.VerifyIssuerSignature(credential)
//	if err != nil {
//		t.Fatal(err)
//	}
//	err = testOntSdk.Credential.VerifyStatus(credential)
//	if err != nil {
//		t.Fatal(err)
//	}
//	presentationString := "{\"@context\":[\"https://www.w3.org/2018/credentials/v1\",\"https://ontid.ont.io/credentials/v1\"],\"id\":\"urn:uuid:7d0f6ffd-28d5-4954-a92f-38ca6062c746\",\"type\":[\"VerifiablePresentation\",\"CredentialManagerPresentation\"],\"verifiableCredential\":[{\"@context\":[\"https://www.w3.org/2018/credentials/v1\",\"https://ontid.ont.io/credentials/v1\"],\"id\":\"urn:uuid:5375555d-9ea2-4a4b-8318-11c28c9bde48\",\"type\":[\"VerifiableCredential\",\"RelationshipCredential\"],\"issuer\":\"did:ont:AJ4C9aTYxTGUhEpaZdPjFSqCqzMCqJDRUd\",\"issuanceDate\":\"2020-06-29T10:11:36Z\",\"expirationDate\":\"2020-06-30T10:11:36Z\",\"credentialSubject\":[{\"id\":\"did:ont:111111\",\"name\":\"Bob\",\"spouse\":\"Alice\"}],\"credentialStatus\":{\"id\":\"52df370680de17bc5d4262c446f102a0ee0d6312\",\"type\":\"AttestContract\"},\"proof\":{\"type\":\"EcdsaSecp256r1VerificationKey2019\",\"created\":\"2020-06-29T10:11:36Z\",\"proofPurpose\":\"assertionMethod\",\"verificationMethod\":\"did:ont:AJ4C9aTYxTGUhEpaZdPjFSqCqzMCqJDRUd#keys-2\",\"hex\":\"01d899e082ad8644cc01ade2f2eeb9b66443cc518c5d56e5a8ef7a562592a189ef19e2a883eb2d6dd4c4817e8b1841663e56b7cb66aba5dfd2f4f777faeda40bf7\"}},{\"@context\":[\"https://www.w3.org/2018/credentials/v1\",\"https://ontid.ont.io/credentials/v1\"],\"id\":\"urn:uuid:3076ea1d-ef58-425e-8849-82f218ab906e\",\"type\":[\"VerifiableCredential\",\"RelationshipCredential\"],\"issuer\":{\"id\":\"did:ont:AJ4C9aTYxTGUhEpaZdPjFSqCqzMCqJDRUd\",\"name\":\"issuer\"},\"issuanceDate\":\"2020-06-29T10:11:55Z\",\"expirationDate\":\"2020-06-30T10:11:36Z\",\"credentialSubject\":[{\"id\":\"did:ont:111111\",\"name\":\"he\",\"spouse\":\"she\"}],\"credentialStatus\":{\"id\":\"52df370680de17bc5d4262c446f102a0ee0d6312\",\"type\":\"AttestContract\"},\"proof\":{\"type\":\"EcdsaSecp256r1VerificationKey2019\",\"created\":\"2020-06-29T10:11:55Z\",\"proofPurpose\":\"assertionMethod\",\"verificationMethod\":\"did:ont:AJ4C9aTYxTGUhEpaZdPjFSqCqzMCqJDRUd#keys-2\",\"hex\":\"018691f221e88ed5aae4eca1f991fb82c3ea1fe04d637ee03bc42b9118ae4511a66f992ddac6c678f5f472ddb4052929747267a64286f11155318e2b53e8f86af1\"}}],\"holder\":\"did:ont:AVe4zVZzteo6HoLpdBwpKNtDXLjJBzB9fv\",\"proof\":[{\"type\":\"EcdsaSecp256r1VerificationKey2019\",\"created\":\"2020-06-29T10:12:14Z\",\"challenge\":\"d1b23d3...3d23d32d2\",\"domain\":[\"https://example.com\"],\"proofPurpose\":\"assertionMethod\",\"verificationMethod\":\"did:ont:AVe4zVZzteo6HoLpdBwpKNtDXLjJBzB9fv#keys-2\",\"hex\":\"01673ba58f0a4d03120713c8b81865dcf52be29d516d7f4420e9d490191d97f843475f9b06d2f45b7d9cb7c80edfa95e82ea5272e781dcda335cbe4837d5a836cd\"}]}"
//	presentation := &VerifiablePresentation{}
//	if err := json.Unmarshal([]byte(presentationString), presentation); err != nil {
//		t.Fatal(err)
//	}
//	for i := range presentation.Proof {
//		_, err = testOntSdk.Credential.VerifyPresentationProof(presentation, i)
//		if err != nil {
//			t.Fatal(err)
//		}
//	}
//}
