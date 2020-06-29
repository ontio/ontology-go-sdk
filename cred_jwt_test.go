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

func TestVerifyStringJWT(t *testing.T) {
	Init()

	credibleOntIds := []string{"did:ont:AJ4C9aTYxTGUhEpaZdPjFSqCqzMCqJDRUd",
		"did:ont:AVe4zVZzteo6HoLpdBwpKNtDXLjJBzB9fv"}
	jwtCred := "eyJhbGciOiJFUzI1NiIsImtpZCI6ImRpZDpvbnQ6QUo0QzlhVFl4VEdVaEVwYVpkUGpGU3FDcXpNQ3FKRFJVZCNrZXlzLTIiLCJ0eXAiOiJKV1QifQ==.eyJpc3MiOiJkaWQ6b250OkFKNEM5YVRZeFRHVWhFcGFaZFBqRlNxQ3F6TUNxSkRSVWQiLCJzdWIiOiJkaWQ6b250OjExMTExMSIsImV4cCI6MTU5MzUwODg0NywibmJmIjoxNTkzNDIyNDQ3LCJpYXQiOjE1OTM0MjI0NDcsImp0aSI6InVybjp1dWlkOjBjNjM5NzIwLWRjNGEtNGE1YS1hZTJmLTI4ZDgzNDg2ZDc4ZCIsInZjIjp7IkBjb250ZXh0IjpbImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL3YxIiwiaHR0cHM6Ly9vbnRpZC5vbnQuaW8vY3JlZGVudGlhbHMvdjEiXSwidHlwZSI6WyJWZXJpZmlhYmxlQ3JlZGVudGlhbCIsIlJlbGF0aW9uc2hpcENyZWRlbnRpYWwiXSwiY3JlZGVudGlhbFN1YmplY3QiOnsibmFtZSI6IkJvYiIsInNwb3VzZSI6IkFsaWNlIn0sImNyZWRlbnRpYWxTdGF0dXMiOnsiaWQiOiI1MmRmMzcwNjgwZGUxN2JjNWQ0MjYyYzQ0NmYxMDJhMGVlMGQ2MzEyIiwidHlwZSI6IkF0dGVzdENvbnRyYWN0In0sInByb29mIjp7ImNyZWF0ZWQiOiIyMDIwLTA2LTI5VDE3OjIwOjQ3WiIsInByb29mUHVycG9zZSI6ImFzc2VydGlvbk1ldGhvZCJ9fX0=.AZJzqbjmW8g5GNLn9QTgFGA86d4DIPd8A/rkoj5M+VNMsF76VteiHLy/j1srO8rORX36Xzp6ajIZ6NIMmBRH6M8="
	err := testOntSdk.Credential.VerifyJWTCredibleOntId(credibleOntIds, jwtCred)
	if err != nil {
		t.Fatal(err)
	}
	err = testOntSdk.Credential.VerifyJWTDate(jwtCred)
	if err != nil {
		t.Fatal(err)
	}
	err = testOntSdk.Credential.VerifyJWTIssuerSignature(jwtCred)
	if err != nil {
		t.Fatal(err)
	}
	err = testOntSdk.Credential.VerifyJWTStatus(jwtCred)
	if err != nil {
		t.Fatal(err)
	}
	jwtPresentation := "eyJhbGciOiJFUzI1NiIsImtpZCI6ImRpZDpvbnQ6QVZlNHpWWnp0ZW82SG9McGRCd3BLTnREWExqSkJ6QjlmdiNrZXlzLTIiLCJ0eXAiOiJKV1QifQ==.eyJpc3MiOiJkaWQ6b250OkFWZTR6Vlp6dGVvNkhvTHBkQndwS050RFhMakpCekI5ZnYiLCJhdWQiOlsiaHR0cHM6Ly9leGFtcGxlLmNvbSJdLCJqdGkiOiJ1cm46dXVpZDo1ODU3ZDdiMS04ZDM5LTRmMzktOTYwNi0xNGRjNjIwZjExYzciLCJub25jZSI6ImQxYjIzZDMuLi4zZDIzZDMyZDIiLCJ2cCI6eyJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvMjAxOC9jcmVkZW50aWFscy92MSIsImh0dHBzOi8vb250aWQub250LmlvL2NyZWRlbnRpYWxzL3YxIl0sInR5cGUiOlsiVmVyaWZpYWJsZVByZXNlbnRhdGlvbiIsIkNyZWRlbnRpYWxNYW5hZ2VyUHJlc2VudGF0aW9uIl0sInZlcmlmaWFibGVDcmVkZW50aWFsIjpbImV5SmhiR2NpT2lKRlV6STFOaUlzSW10cFpDSTZJbVJwWkRwdmJuUTZRVW8wUXpsaFZGbDRWRWRWYUVWd1lWcGtVR3BHVTNGRGNYcE5RM0ZLUkZKVlpDTnJaWGx6TFRJaUxDSjBlWEFpT2lKS1YxUWlmUT09LmV5SnBjM01pT2lKa2FXUTZiMjUwT2tGS05FTTVZVlJaZUZSSFZXaEZjR0ZhWkZCcVJsTnhRM0Y2VFVOeFNrUlNWV1FpTENKemRXSWlPaUprYVdRNmIyNTBPakV4TVRFeE1TSXNJbVY0Y0NJNk1UVTVNelV3T0RnME55d2libUptSWpveE5Ua3pOREl5TkRRM0xDSnBZWFFpT2pFMU9UTTBNakkwTkRjc0ltcDBhU0k2SW5WeWJqcDFkV2xrT2pCak5qTTVOekl3TFdSak5HRXROR0UxWVMxaFpUSm1MVEk0WkRnek5EZzJaRGM0WkNJc0luWmpJanA3SWtCamIyNTBaWGgwSWpwYkltaDBkSEJ6T2k4dmQzZDNMbmN6TG05eVp5OHlNREU0TDJOeVpXUmxiblJwWVd4ekwzWXhJaXdpYUhSMGNITTZMeTl2Ym5ScFpDNXZiblF1YVc4dlkzSmxaR1Z1ZEdsaGJITXZkakVpWFN3aWRIbHdaU0k2V3lKV1pYSnBabWxoWW14bFEzSmxaR1Z1ZEdsaGJDSXNJbEpsYkdGMGFXOXVjMmhwY0VOeVpXUmxiblJwWVd3aVhTd2lZM0psWkdWdWRHbGhiRk4xWW1wbFkzUWlPbnNpYm1GdFpTSTZJa0p2WWlJc0luTndiM1Z6WlNJNklrRnNhV05sSW4wc0ltTnlaV1JsYm5ScFlXeFRkR0YwZFhNaU9uc2lhV1FpT2lJMU1tUm1NemN3Tmpnd1pHVXhOMkpqTldRME1qWXlZelEwTm1ZeE1ESmhNR1ZsTUdRMk16RXlJaXdpZEhsd1pTSTZJa0YwZEdWemRFTnZiblJ5WVdOMEluMHNJbkJ5YjI5bUlqcDdJbU55WldGMFpXUWlPaUl5TURJd0xUQTJMVEk1VkRFM09qSXdPalEzV2lJc0luQnliMjltVUhWeWNHOXpaU0k2SW1GemMyVnlkR2x2YmsxbGRHaHZaQ0o5ZlgwPS5BWkp6cWJqbVc4ZzVHTkxuOVFUZ0ZHQTg2ZDRESVBkOEEvcmtvajVNK1ZOTXNGNzZWdGVpSEx5L2oxc3JPOHJPUlgzNlh6cDZhaklaNk5JTW1CUkg2TTg9IiwiZXlKaGJHY2lPaUpGVXpJMU5pSXNJbXRwWkNJNkltUnBaRHB2Ym5RNlFVbzBRemxoVkZsNFZFZFZhRVZ3WVZwa1VHcEdVM0ZEY1hwTlEzRktSRkpWWkNOclpYbHpMVElpTENKMGVYQWlPaUpLVjFRaWZRPT0uZXlKcGMzTWlPaUprYVdRNmIyNTBPa0ZLTkVNNVlWUlplRlJIVldoRmNHRmFaRkJxUmxOeFEzRjZUVU54U2tSU1ZXUWlMQ0psZUhBaU9qRTFPVE0xTURnNE5EY3NJbTVpWmlJNk1UVTVNelF5TWpRMk5pd2lhV0YwSWpveE5Ua3pOREl5TkRZMkxDSnFkR2tpT2lKMWNtNDZkWFZwWkRvelpXRXhaamd4TWkweU1tUTVMVFE0WTJVdFlXSTNNeTFqTURWbE5qWTJObUpoTURNaUxDSjJZeUk2ZXlKQVkyOXVkR1Y0ZENJNld5Sm9kSFJ3Y3pvdkwzZDNkeTUzTXk1dmNtY3ZNakF4T0M5amNtVmtaVzUwYVdGc2N5OTJNU0lzSW1oMGRIQnpPaTh2YjI1MGFXUXViMjUwTG1sdkwyTnlaV1JsYm5ScFlXeHpMM1l4SWwwc0luUjVjR1VpT2xzaVZtVnlhV1pwWVdKc1pVTnlaV1JsYm5ScFlXd2lMQ0pTWld4aGRHbHZibk5vYVhCRGNtVmtaVzUwYVdGc0lsMHNJbWx6YzNWbGNpSTZleUp1WVcxbElqb2lhWE56ZFdWeUluMHNJbU55WldSbGJuUnBZV3hUZFdKcVpXTjBJanBiZXlKcFpDSTZJbVJwWkRwdmJuUTZNVEV4TVRFeElpd2libUZ0WlNJNkltaGxJaXdpYzNCdmRYTmxJam9pYzJobEluMWRMQ0pqY21Wa1pXNTBhV0ZzVTNSaGRIVnpJanA3SW1sa0lqb2lOVEprWmpNM01EWTRNR1JsTVRkaVl6VmtOREkyTW1NME5EWm1NVEF5WVRCbFpUQmtOak14TWlJc0luUjVjR1VpT2lKQmRIUmxjM1JEYjI1MGNtRmpkQ0o5TENKd2NtOXZaaUk2ZXlKamNtVmhkR1ZrSWpvaU1qQXlNQzB3TmkweU9WUXhOem95TVRvd05sb2lMQ0p3Y205dlpsQjFjbkJ2YzJVaU9pSmhjM05sY25ScGIyNU5aWFJvYjJRaWZYMTkuQVoyK1dWS3cxU2VUaG44d3loQlZpaVpZSmdramM4clc5SkI1WThrSHRNL1hrRmV6blRrcTUxd3poM1lpTWovYm80TjRNRDNpRkVwc1lHZ0VPMlVsRzc0PSJdLCJwcm9vZiI6eyJjcmVhdGVkIjoiMjAyMC0wNi0yOVQxNzoyMToyNVoiLCJwcm9vZlB1cnBvc2UiOiJhc3NlcnRpb25NZXRob2QifX19.AXtE9ZnANmyoy72CBhImXl2/SDIohriYdjavOyn9uv8h8OBkSyBo/l898N3vxhlSxlXHnLfyRzJ8aGGICtWiKC4="
	err = testOntSdk.Credential.VerifyJWTIssuerSignature(jwtPresentation)
	if err != nil {
		t.Fatal(err)
	}
}
