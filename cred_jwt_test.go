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

func TestJWTCredential(t *testing.T) {
	Init()

	testOntSdk.SetCredContractAddress("52df370680de17bc5d4262c446f102a0ee0d6312")
	issuer, err := testWallet.NewDefaultSettingIdentity(testPasswd)
	if err != nil {
		t.Errorf("TestJWTCredential NewDefaultSettingIdentity error:%s", err)
		return
	}
	holder, err := testWallet.NewDefaultSettingIdentity(testPasswd)
	if err != nil {
		t.Errorf("TestJWTCredential NewDefaultSettingIdentity error:%s", err)
		return
	}

	_, err = testOntSdk.Native.OntId.RegIDWithPublicKey(testGasPrice, testGasLimit, testDefAcc, issuer.ID, testDefAcc)
	if err != nil {
		t.Errorf("TestJWTCredential RegIDWithPublicKey error:%s", err)
		return
	}
	_, err = testOntSdk.Native.OntId.RegIDWithPublicKey(testGasPrice, testGasLimit, testDefAcc, holder.ID, testDefAcc)
	if err != nil {
		t.Errorf("TestJWTCredential RegIDWithPublicKey error:%s", err)
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
		t.Errorf("TestJWTCredential testOntSdk.Credential.GenSignReq error:%s", err)
		return
	}

	err = testOntSdk.Credential.VerifySignReq(request)
	if err != nil {
		t.Errorf("TestJWTCredential testOntSdk.Credential.VerifySignReq error:%s", err)
		return
	}

	contexts := []string{"context1", "context2"}
	types := []string{"RelationshipCredential"}
	expirationDate := time.Now().UTC().Unix() + 86400
	s, err := testOntSdk.Credential.CreateJWTCredential(contexts, types, credentialSubject, issuer.ID, expirationDate,
		"", "", testDefAcc)
	if err != nil {
		t.Errorf("TestJWTCredential testOntSdk.Credential.CreateCredential error:%s", err)
		return
	}
	fmt.Println("JWTcredential is: ", s)
	cred, err := DeserializeJWT(s)
	if err != nil {
		t.Errorf("TestJWTCredential DeserializeJWT error:%s", err)
		return
	}

	contractAddress, err := common.AddressFromHexString(cred.Payload.VC.CredentialStatus.Id)
	if err != nil {
		t.Errorf("TestJWTCredential common.AddressFromHexString:%s", err)
		return
	}
	txHash, err := testOntSdk.Credential.CommitCredential(contractAddress, 500, 20000, cred.Payload.Jti,
		issuer.ID, holder.ID, testDefAcc, testDefAcc)
	if err != nil {
		t.Errorf("TestJWTCredential testOntSdk.Credential.CommitCredential error:%s", err)
		return
	}
	fmt.Println("txHash 1 is: ", txHash.ToHexString())
	testOntSdk.WaitForGenerateBlock(30 * time.Second)

	err = testOntSdk.Credential.VerifyJWTCredibleOntId([]string{issuer.ID}, s)
	if err != nil {
		t.Errorf("TestJWTCredential testOntSdk.Credential.VerifyCredibleOntId error:%s", err)
		return
	}
	err = testOntSdk.Credential.VerifyJWTDate(s)
	if err != nil {
		t.Errorf("TestJWTCredential testOntSdk.Credential.VerifyDate error:%s", err)
		return
	}
	err = testOntSdk.Credential.VerifyJWTIssuerSignature(s)
	if err != nil {
		t.Errorf("TestJWTCredential testOntSdk.Credential.VerifyIssuerSignature credential error:%s", err)
		return
	}
	err = testOntSdk.Credential.VerifyJWTStatus(s)
	if err != nil {
		t.Errorf("TestJWTCredential testOntSdk.Credential.VerifyStatus error:%s", err)
		return
	}

	ps, err := testOntSdk.Credential.CreateJWTPresentation([]string{s}, contexts, types, holder.ID,
		"", "", testDefAcc)
	if err != nil {
		t.Errorf("TestJWTCredential testOntSdk.Credential.CreatePresentation error:%s", err)
		return
	}
	fmt.Println("JWTPresentation is: ", ps)

	err = testOntSdk.Credential.VerifyJWTIssuerSignature(ps)
	if err != nil {
		t.Errorf("TestJWTCredential testOntSdk.Credential.VerifyIssuerSignature presentation error:%s", err)
		return
	}

	credential, err := testOntSdk.Credential.JWTCred2Json(s)
	if err != nil {
		t.Errorf("TestJWTCredential testOntSdk.Credential.JWTCred2Json error:%s", err)
		return
	}
	credentialJson, err := json.Marshal(credential)
	if err != nil {
		t.Errorf("TestJWTCredential json.Marshal credential error:%s", err)
		return
	}
	fmt.Println("credential is: ", string(credentialJson))

	presentation, err := testOntSdk.Credential.JWTPresentation2Json(ps)
	if err != nil {
		t.Errorf("TestJWTCredential testOntSdk.Credential.JWTPresentation2Json error:%s", err)
		return
	}
	presentationJson, err := json.Marshal(presentation)
	if err != nil {
		t.Errorf("TestJWTCredential json.Marshal presentation error:%s", err)
		return
	}
	fmt.Println("presentation is: ", string(presentationJson))

	s2, err := testOntSdk.Credential.JsonCred2JWT(credential)
	if err != nil {
		t.Errorf("TestJWTCredential testOntSdk.Credential.JsonCred2JWT error:%s", err)
		return
	}
	fmt.Println("JWTcredential2 is: ", s2)

	ps2, err := testOntSdk.Credential.JsonPresentation2JWT(presentation, presentation.Proof[0])
	if err != nil {
		t.Errorf("TestJWTCredential testOntSdk.Credential.JsonCred2JWT error:%s", err)
		return
	}
	fmt.Println("JWTPresentation2 is: ", ps2)

	credential2, err := testOntSdk.Credential.JWTCred2Json(s2)
	if err != nil {
		t.Errorf("TestJWTCredential testOntSdk.Credential.JWTCred2Json error:%s", err)
		return
	}
	credentialJson2, err := json.Marshal(credential2)
	if err != nil {
		t.Errorf("TestJWTCredential json.Marshal credential error:%s", err)
		return
	}
	fmt.Println("credential2 is: ", string(credentialJson2))

	presentation2, err := testOntSdk.Credential.JWTPresentation2Json(ps2)
	if err != nil {
		t.Errorf("TestJWTCredential testOntSdk.Credential.JWTPresentation2Json error:%s", err)
		return
	}
	presentationJson2, err := json.Marshal(presentation2)
	if err != nil {
		t.Errorf("TestJWTCredential json.Marshal presentation error:%s", err)
		return
	}
	fmt.Println("presentation2 is: ", string(presentationJson2))

	txHash, err = testOntSdk.Credential.RevokeJWTCredentialByHolder(500, 20000, s, holder.ID, testDefAcc, testDefAcc)
	if err != nil {
		t.Errorf("TestJWTCredential testOntSdk.Credential.RevokeCredentialByHolder error:%s", err)
		return
	}
	fmt.Println("txHash 2 is: ", txHash.ToHexString())
	testOntSdk.WaitForGenerateBlock(30 * time.Second)

	txHash, err = testOntSdk.Credential.RemoveJWTCredential(500, 20000, s, holder.ID, testDefAcc, testDefAcc)
	if err != nil {
		t.Errorf("TestJWTCredential testOntSdk.Credential.RevokeCredentialByHolder error:%s", err)
		return
	}
	fmt.Println("txHash 3 is: ", txHash.ToHexString())
}
