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
	"encoding/hex"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"time"

	"github.com/ontio/ontology-crypto/keypair"
	"github.com/ontio/ontology/common"
	"github.com/ontio/ontology/core/signature"
	uuid "github.com/satori/go.uuid"
)

const (
	CREDENTIAL_STATUS_TYPE CredentialStatusType = "AttestContract"
	PROOF_PURPOSE          ProofPurpose         = "assertionMethod"
	UUID_PREFIX                                 = "urn:uuid:"
)

type CredentialStatusType string
type ProofPurpose string

var DefaultContext = []string{"https://www.w3.org/2018/credentials/v1", "https://ontid.ont.io/credentials/v1"}
var DefaultCredentialType = []string{"VerifiableCredential"}
var DefaultPresentationType = []string{"VerifiablePresentation"}

type Credential struct {
	credRecordContractAddress common.Address
	ontSdk                    *OntologySdk
}

type Request struct {
	CredentialSubject interface{} `json:"credentialSubject,omitempty"`
	OntId             string      `json:"ontId,omitempty"`
	Proof             *Proof      `json:"proof,omitempty"`
}

type CredentialStatus struct {
	Id   string               `json:"id"`
	Type CredentialStatusType `json:"type"`
}

type Proof struct {
	Type               string       `json:"type,omitempty"`
	Created            string       `json:"created,omitempty"`
	Challenge          string       `json:"challenge,omitempty"`
	Domain             interface{}  `json:"domain,omitempty"`
	ProofPurpose       ProofPurpose `json:"proofPurpose,omitempty"`
	VerificationMethod string       `json:"verificationMethod,omitempty"`
	Hex                string       `json:"hex,omitempty"`
	Jws                string       `json:"jws,omitempty"`
}

type VerifiableCredential struct {
	Context           []string          `json:"@context,omitempty"`
	Id                string            `json:"id,omitempty"`
	Type              []string          `json:"type,omitempty"`
	Issuer            interface{}       `json:"issuer,omitempty"`
	IssuanceDate      string            `json:"issuanceDate,omitempty"`
	ExpirationDate    string            `json:"expirationDate,omitempty"`
	CredentialSubject interface{}       `json:"credentialSubject,omitempty"`
	CredentialStatus  *CredentialStatus `json:"credentialStatus,omitempty"`
	Proof             *Proof            `json:"proof,omitempty"`
}

type VerifiablePresentation struct {
	Context              []string                `json:"@context,omitempty"`
	Id                   string                  `json:"id,omitempty"`
	Type                 []string                `json:"type,omitempty"`
	VerifiableCredential []*VerifiableCredential `json:"verifiableCredential,omitempty"`
	Holder               interface{}             `json:"holder,omitempty"`
	Proof                []*Proof                `json:"proof,omitempty"`
}

type PublicKeyList []*PublicKey

type PublicKey struct {
	Id           string `json:"id"`
	Type         string `json:"type"`
	PublicKeyHex string `json:"publicKeyHex"`
}

func newCredential(ontSdk *OntologySdk) *Credential {
	return &Credential{
		ontSdk: ontSdk,
	}
}

func (this *Credential) GenSignReq(credentialSubject interface{}, ontId string, signer *Account) (*Request, error) {
	request := &Request{
		CredentialSubject: credentialSubject,
		OntId:             ontId,
	}
	var domain interface{}
	proof, err := this.createProof(ontId, signer, "", domain, time.Now().UTC().Unix())
	if err != nil {
		return nil, fmt.Errorf("GenSignReq, this.CreateProof error: %s", err)
	}
	request.Proof = proof

	msg, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("GenSignReq, json.Marshal error: %s", err)
	}
	sig, err := signer.Sign(msg)
	if err != nil {
		return nil, fmt.Errorf("GenSignReq, signer.Sign error: %s", err)
	}
	request.Proof.Hex = hex.EncodeToString(sig)

	return request, nil
}

func (this *Credential) VerifySignReq(request *Request) error {
	msg, err := GenRequestMsg(request)
	if err != nil {
		return fmt.Errorf("VerifySignReq, hex.DecodeString signature error: %s", err)
	}
	sig, err := hex.DecodeString(request.Proof.Hex)
	if err != nil {
		return fmt.Errorf("VerifySignReq, hex.DecodeString signature error: %s", err)
	}

	publicKeyList, err := this.GetPublicKeyList(request.OntId)
	if err != nil {
		return fmt.Errorf("VerifySignReq, this.GetPublicKeyList error: %s", err)
	}
	for _, v := range publicKeyList {
		data, err := hex.DecodeString(v.PublicKeyHex)
		if err != nil {
			return fmt.Errorf("VerifySignReq, hex.DecodeString public key error: %s", err)
		}
		pk, err := keypair.DeserializePublicKey(data)
		if err != nil {
			return fmt.Errorf("VerifySignReq, keypair.DeserializePublicKey error: %s", err)
		}
		err = signature.Verify(pk, msg, sig)
		if err == nil {
			return nil
		}
	}
	return fmt.Errorf("VerifySignReq failed")
}

func (this *Credential) CreateCredential(contexts []string, types []string, credentialSubject interface{}, issuerId interface{},
	expirationDateTimestamp int64, challenge string, domain interface{}, signer *Account) (*VerifiableCredential, error) {
	credential := new(VerifiableCredential)
	credential.Id = UUID_PREFIX + uuid.NewV4().String()
	credential.Context = append(DefaultContext, contexts...)
	credential.Type = append(DefaultCredentialType, types...)
	credential.Issuer = issuerId

	now := time.Now().UTC().Unix()
	issuanceDate := time.Unix(now, 0).UTC().Format("2006-01-02T15:04:05Z")
	credential.IssuanceDate = issuanceDate

	if expirationDateTimestamp != 0 {
		expirationDate := time.Unix(expirationDateTimestamp, 0).UTC().Format("2006-01-02T15:04:05Z")
		credential.ExpirationDate = expirationDate
		if now > expirationDateTimestamp {
			return nil, fmt.Errorf("CreateCredential, now is after expirationDateTimestamp")
		}
	}
	credential.CredentialSubject = credentialSubject

	credentialStatus := &CredentialStatus{
		Id:   this.credRecordContractAddress.ToHexString(),
		Type: CREDENTIAL_STATUS_TYPE,
	}
	credential.CredentialStatus = credentialStatus

	// create proof
	_, ontId, err := getOntId(issuerId)
	if err != nil {
		return nil, fmt.Errorf("CreateCredential, getOntId error: %s", err)
	}
	proof, err := this.createProof(ontId, signer, challenge, domain, now)
	if err != nil {
		return nil, fmt.Errorf("CreateCredential, this.CreateProof error: %s", err)
	}
	credential.Proof = proof

	msg, err := json.Marshal(credential)
	if err != nil {
		return nil, fmt.Errorf("CreateCredential, json.Marshal credential error: %s", err)
	}
	sig, err := signer.Sign(msg)
	if err != nil {
		return nil, fmt.Errorf("CreateCredential, signer.Sign error: %s", err)
	}
	credential.Proof.Hex = hex.EncodeToString(sig)

	return credential, nil
}

func (this *Credential) GetPublicKeyId(ontId string, publicKeyHex string) (uint32, *PublicKey, error) {
	publicKeyList, err := this.GetPublicKeyList(ontId)
	if err != nil {
		return 0, nil, fmt.Errorf("GetPublicKeyId, this.GetPublicKeyList error: %s", err)
	}

	for i, v := range publicKeyList {
		if v.PublicKeyHex == publicKeyHex {
			return uint32(i + 1), v, nil
		}
	}
	return 0, nil, fmt.Errorf("GetPublicKeyId, record not found")
}

func (this *Credential) GetPublicKey(ontId string, Id string) (string, error) {
	publicKeyList, err := this.GetPublicKeyList(ontId)
	if err != nil {
		return "", fmt.Errorf("GetPublicKeyId, this.GetPublicKeyList error: %s", err)
	}

	for _, v := range publicKeyList {
		if v.Id == Id {
			return v.PublicKeyHex, nil
		}
	}
	return "", fmt.Errorf("GetPublicKeyId, record not found")
}

func (this *Credential) GetPublicKeyList(ontId string) (PublicKeyList, error) {
	publicKeys, err := this.ontSdk.Native.OntId.GetPublicKeysJson(ontId)
	if err != nil {
		return nil, fmt.Errorf("GetPublicKeyList, this.ontSdk.Native.OntId.GetPublicKeysJson error: %s", err)
	}

	var publicKeyList PublicKeyList
	err = json.Unmarshal(publicKeys, &publicKeyList)
	if err != nil {
		return nil, fmt.Errorf("GetPublicKeyList, json.Unmarshal publicKeyList error: %s", err)
	}

	return publicKeyList, nil
}

func (this *Credential) CommitCredential(contractAddress common.Address, gasPrice, gasLimit uint64, credentialId, issuerId,
	holderId string, signer, payer *Account) (common.Uint256, error) {
	index, _, err := this.GetPublicKeyId(issuerId, hex.EncodeToString(keypair.SerializePublicKey(signer.GetPublicKey())))
	if err != nil {
		return common.UINT256_EMPTY, fmt.Errorf("CommitCredential, this.GetPublicKeyId error: %s", err)
	}
	params := []interface{}{"Commit", []interface{}{credentialId, issuerId, index, holderId}}
	txHash, err := this.ontSdk.NeoVM.InvokeNeoVMContract(gasPrice, gasLimit, payer, signer, contractAddress, params)
	if err != nil {
		return common.UINT256_EMPTY, fmt.Errorf("CommitCredential, this.ontSdk.NeoVM.InvokeNeoVMContract error: %s", err)
	}
	return txHash, nil
}

func (this *Credential) revokeCredential(contractAddress common.Address, gasPrice, gasLimit uint64, credentialId, ontId string, index uint32,
	signer, payer *Account) (common.Uint256, error) {
	params := []interface{}{"Revoke", []interface{}{credentialId, ontId, index}}
	txHash, err := this.ontSdk.NeoVM.InvokeNeoVMContract(gasPrice, gasLimit, payer, signer, contractAddress, params)
	if err != nil {
		return common.UINT256_EMPTY, fmt.Errorf("revokeCredential, this.ontSdk.NeoVM.InvokeNeoVMContract error: %s", err)
	}
	return txHash, nil
}

func (this *Credential) RemoveCredential(gasPrice, gasLimit uint64, credential *VerifiableCredential, ontId string,
	signer, payer *Account) (common.Uint256, error) {
	index, _, err := this.GetPublicKeyId(ontId, hex.EncodeToString(keypair.SerializePublicKey(signer.GetPublicKey())))
	if err != nil {
		return common.UINT256_EMPTY, fmt.Errorf("RemoveCredential, this.GetPublicKeyId error: %s", err)
	}
	if credential.CredentialStatus.Type != CREDENTIAL_STATUS_TYPE {
		return common.UINT256_EMPTY, fmt.Errorf("RemoveCredential, credential status  %s not match", credential.CredentialStatus.Type)
	}
	contractAddress, err := common.AddressFromHexString(credential.CredentialStatus.Id)
	if err != nil {
		return common.UINT256_EMPTY, fmt.Errorf("RemoveCredential, common.AddressFromHexString error: %s", err)
	}
	params := []interface{}{"Remove", []interface{}{credential.Id, ontId, index}}
	txHash, err := this.ontSdk.NeoVM.InvokeNeoVMContract(gasPrice, gasLimit, payer, signer, contractAddress, params)
	if err != nil {
		return common.UINT256_EMPTY, fmt.Errorf("RemoveCredential, this.ontSdk.NeoVM.InvokeNeoVMContract error: %s", err)
	}
	return txHash, nil
}

func (this *Credential) VerifyCredibleOntId(credibleOntIds []string, credential *VerifiableCredential) error {
	for _, v := range credibleOntIds {
		if credential.Issuer == v {
			return nil
		}
	}
	return fmt.Errorf("VerifyCredibleOntId failed")
}

func (this *Credential) VerifyExpirationDate(credential *VerifiableCredential) error {
	now := time.Now().UTC()
	if credential.ExpirationDate != "" {
		expirationDate, err := time.Parse("2006-01-02T15:04:05Z", credential.ExpirationDate)
		if err != nil {
			return fmt.Errorf("VerifyExpirationDate error: %s", err)
		}
		if now.Unix() > expirationDate.Unix() {
			return fmt.Errorf("VerifyExpirationDate expirationDate failed")
		}
	}
	return nil
}

func (this *Credential) VerifyIssuanceDate(credential *VerifiableCredential) error {
	now := time.Now().UTC()
	issuanceDate, err := time.Parse("2006-01-02T15:04:05Z", credential.IssuanceDate)
	if err != nil {
		return fmt.Errorf("VerifyIssuanceDate error: %s", err)
	}
	if now.Unix() < issuanceDate.Unix() {
		return fmt.Errorf("VerifyIssuanceDate issuanceDate failed")
	}
	return nil
}

func (this *Credential) VerifyIssuerSignature(credential *VerifiableCredential) error {
	msg, err := GenCredentialMsg(credential)
	if err != nil {
		return fmt.Errorf("VerifyIssuerSignature, GenCredentialMsg error: %s", err)
	}
	_, ontId, err := getOntId(credential.Issuer)
	if err != nil {
		return fmt.Errorf("VerifyIssuerSignature, getOntId error: %s", err)
	}
	err = this.verifyProof(ontId, credential.Proof, msg)
	if err != nil {
		return fmt.Errorf("VerifyIssuerSignature, this.VerifyProof error: %s", err)
	}
	return nil
}

func (this *Credential) VerifyStatus(credential *VerifiableCredential) error {
	if credential.CredentialStatus.Type != CREDENTIAL_STATUS_TYPE {
		return fmt.Errorf("VerifyStatus, credential status  %s not match", credential.CredentialStatus.Type)
	}
	contractAddress, err := common.AddressFromHexString(credential.CredentialStatus.Id)
	if err != nil {
		return fmt.Errorf("VerifyStatus, common.AddressFromHexString error: %s", err)
	}
	status, err := this.getCredentialStatus(contractAddress, credential.Id)
	if err != nil {
		return fmt.Errorf("VerifyStatus, this.getCredentialStatus error: %s", err)
	}
	if status != 1 {
		return fmt.Errorf("VerifyStatus failed")
	}
	return nil
}

func (this *Credential) getCredentialStatus(contractAddress common.Address, credentialId string) (uint64, error) {
	params := []interface{}{"GetStatus", []interface{}{credentialId}}
	preExecResult, err := this.ontSdk.NeoVM.PreExecInvokeNeoVMContract(contractAddress, params)
	if err != nil {
		return 0, fmt.Errorf("getCredentialStatus, this.ontSdk.NeoVM.PreExecInvokeNeoVMContract error: %s", err)
	}
	r, err := preExecResult.Result.ToInteger()
	if err != nil {
		return 0, fmt.Errorf("getCredentialStatus, preExecResult.Result.ToInteger error: %s", err)
	}
	return r.Uint64(), nil
}

func (this *Credential) CreatePresentation(credentials []*VerifiableCredential, contexts, types []string, holder interface{},
	signerOntIds, challenge []string, domain []interface{}, signers []*Account) (*VerifiablePresentation, error) {
	presentation := new(VerifiablePresentation)
	presentation.Id = UUID_PREFIX + uuid.NewV4().String()
	presentation.Context = append(DefaultContext, contexts...)
	presentation.Type = append(DefaultPresentationType, types...)
	presentation.Holder = holder
	presentation.VerifiableCredential = credentials

	if !(len(signerOntIds) == len(challenge) && len(signerOntIds) == len(domain) && len(signerOntIds) == len(signers)) {
		return nil, fmt.Errorf("input params error")
	}
	now := time.Now().UTC().Unix()
	proofs := make([]*Proof, 0)
	for i := range signerOntIds {
		// create proof
		proof, err := this.createProof(signerOntIds[i], signers[i], challenge[i], domain[i], now)
		if err != nil {
			return nil, fmt.Errorf("CreatePresentation, this.CreateProof error: %s", err)
		}
		presentation.Proof = []*Proof{proof}
		msg, err := json.Marshal(presentation)
		if err != nil {
			return nil, fmt.Errorf("CreatePresentation, json.Marshal msg error: %s", err)
		}
		sig, err := signers[i].Sign(msg)
		if err != nil {
			return nil, fmt.Errorf("CreatePresentation, signer.Sign error: %s", err)
		}
		proof.Hex = hex.EncodeToString(sig)
		proofs = append(proofs, proof)
	}
	presentation.Proof = proofs
	return presentation, nil
}

func (this *Credential) VerifyPresentationProof(presentation *VerifiablePresentation, index int) (string, error) {
	msg, err := GenPresentationMsg(presentation)
	if err != nil {
		return "", fmt.Errorf("VerifyPresentationProof, GenPresentationMsg error: %s", err)
	}
	ontId := parseOntId(presentation.Proof[index].VerificationMethod)
	err = this.verifyProof(ontId, presentation.Proof[index], msg)
	if err != nil {
		return "", fmt.Errorf("VerifyPresentationProof, this.VerifyProof error: %s", err)
	}
	return ontId, nil
}

func (this *Credential) JsonCred2JWT(cred *VerifiableCredential) (string, error) {
	is, ontId, err := getOntId(cred.Issuer)
	if err != nil {
		return "", fmt.Errorf("JsonCred2JWT, getOntId issuer error: %s", err)
	}
	header, err := makeJWTHeader(cred.Proof.Type, cred.Proof.VerificationMethod)
	if err != nil {
		return "", fmt.Errorf("JsonCred2JWT, makeJWTHeader error: %s", err)
	}

	cs, sub, err := getOntId(cred.CredentialSubject)
	if err != nil {
		return "", fmt.Errorf("JsonCred2JWT, getOntId credentialSubject error: %s", err)
	}

	proof := cred.Proof
	proof.VerificationMethod = ""
	proof.Type = ""
	vc := &VC{
		Context:           cred.Context,
		Type:              cred.Type,
		Issuer:            is,
		CredentialSubject: cs,
		CredentialStatus:  cred.CredentialStatus,
		Proof:             proof,
	}
	issuanceDate, err := time.Parse("2006-01-02T15:04:05Z", cred.IssuanceDate)
	if err != nil {
		return "", fmt.Errorf("JsonCred2JWT, time.Parse issuanceDate error: %s", err)
	}
	expirationDate, err := time.Parse("2006-01-02T15:04:05Z", cred.ExpirationDate)
	if err != nil {
		return "", fmt.Errorf("JsonCred2JWT, time.Parse expirationDate error: %s", err)
	}
	payload := &Payload{
		Sub: sub,
		Jti: cred.Id,
		Iss: ontId,
		Nbf: issuanceDate.Unix(),
		Iat: issuanceDate.Unix(),
		Exp: expirationDate.Unix(),
		VC:  vc,
	}

	credential := &JWTCredential{
		Header:  header,
		Payload: payload,
	}
	if cred.Proof.Jws == "" {
		return "", fmt.Errorf("JsonCred2JWT, Jws signature is empty")
	}
	credential.Jws = cred.Proof.Jws
	return credential.ToString()
}

func (this *Credential) JsonPresentation2JWT(presentation *VerifiablePresentation, proof *Proof) (string, error) {
	hd, ontId, err := getOntId(presentation.Holder)
	if err != nil {
		return "", fmt.Errorf("JsonPresentation2JWT, getOntId holder error: %s", err)
	}
	header, err := makeJWTHeader(proof.Type, proof.VerificationMethod)
	if err != nil {
		return "", fmt.Errorf("JsonPresentation2JWT, makeJWTHeader error: %s", err)
	}

	proof.VerificationMethod = ""
	proof.Type = ""
	// make credentials
	var credentials []string
	for _, v := range presentation.VerifiableCredential {
		JWTCred, err := this.JsonCred2JWT(v)
		if err != nil {
			return "", fmt.Errorf("JsonPresentation2JWT, this.JsonCred2JWT error: %s", err)
		}
		credentials = append(credentials, JWTCred)
	}
	vp := &VP{
		Context:              presentation.Context,
		Type:                 presentation.Type,
		VerifiableCredential: credentials,
		Holder:               hd,
		Proof:                proof,
	}
	payload := &Payload{
		Aud:   proof.Domain,
		Nonce: proof.Challenge,
		Jti:   presentation.Id,
		Iss:   ontId,
		VP:    vp,
	}

	JWTPresentation := &JWTCredential{
		Header:  header,
		Payload: payload,
	}
	if proof.Jws == "" {
		return "", fmt.Errorf("JsonPresentation2JWT, Jws signature is empty")
	}
	JWTPresentation.Jws = proof.Jws
	return JWTPresentation.ToString()
}

func (this *Credential) verifyProof(ontId string, proof *Proof, msg []byte) error {
	sig, err := hex.DecodeString(proof.Hex)
	if err != nil {
		return fmt.Errorf("VerifyProof, hex.DecodeString signature error: %s", err)
	}

	publicKeyHex, err := this.GetPublicKey(ontId, proof.VerificationMethod)
	if err != nil {
		return fmt.Errorf("VerifyProof, this.GetPublicKey error: %s", err)
	}
	data, err := hex.DecodeString(publicKeyHex)
	if err != nil {
		return fmt.Errorf("VerifyProof, hex.DecodeString public key error: %s", err)
	}
	pk, err := keypair.DeserializePublicKey(data)
	if err != nil {
		return fmt.Errorf("VerifyProof, keypair.DeserializePublicKey error: %s", err)
	}

	return signature.Verify(pk, msg, sig)
}

func (this *Credential) RevokeCredentialByHolder(gasPrice, gasLimit uint64, credential *VerifiableCredential, holder string,
	signer, payer *Account) (common.Uint256, error) {
	if credential.CredentialStatus.Type != CREDENTIAL_STATUS_TYPE {
		return common.UINT256_EMPTY, fmt.Errorf("RevokeCredentialByHolder, credential status  %s not match", credential.CredentialStatus.Type)
	}
	contractAddress, err := common.AddressFromHexString(credential.CredentialStatus.Id)
	if err != nil {
		return common.UINT256_EMPTY, fmt.Errorf("RevokeCredentialByHolder, common.AddressFromHexString error: %s", err)
	}

	index, _, err := this.GetPublicKeyId(holder, hex.EncodeToString(keypair.SerializePublicKey(signer.GetPublicKey())))
	if err != nil {
		return common.UINT256_EMPTY, fmt.Errorf("RevokeCredentialByHolder, this.GetPublicKeyId error: %s", err)
	}

	return this.revokeCredential(contractAddress, gasPrice, gasLimit, credential.Id, holder, index, signer, payer)
}

func (this *Credential) RevokeCredentialByIssuer(gasPrice, gasLimit uint64, credentialId string, issuer string,
	signer, payer *Account) (common.Uint256, error) {
	index, _, err := this.GetPublicKeyId(issuer, hex.EncodeToString(keypair.SerializePublicKey(signer.GetPublicKey())))
	if err != nil {
		return common.UINT256_EMPTY, fmt.Errorf("RevokeCredentialByIssuer, this.GetPublicKeyId error: %s", err)
	}

	return this.revokeCredential(this.credRecordContractAddress, gasPrice, gasLimit, credentialId, issuer, index, signer, payer)
}

func parseOntId(raw string) string {
	return strings.Split(raw, "#")[0]
}

type OntIdObject struct {
	Id string `json:"id"`
}

func genIdObject(ontId string, object interface{}) (interface{}, error) {
	b, err := json.Marshal(object)
	if err != nil {
		return nil, fmt.Errorf("genIdObject, json.Marshal object error: %s", err)
	}
	m := make(map[string]interface{})
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, fmt.Errorf("genIdObject, json.Unmarshal object error: %s", err)
	}
	if m == nil {
		m = make(map[string]interface{})
	}
	m["id"] = ontId

	if len(m) == 1 {
		return ontId, nil
	}
	j, err := json.Marshal(m)
	if err != nil {
		return nil, fmt.Errorf("genIdObject, json.Marshal map object error: %s", err)
	}
	var r interface{}
	if err := json.Unmarshal(j, &r); err != nil {
		return nil, fmt.Errorf("genIdObject, json.Unmarshal result error: %s", err)
	}
	return r, nil
}

func getOntId(raw interface{}) (interface{}, string, error) {
	t := reflect.TypeOf(raw).Kind()
	if t != reflect.Struct && t != reflect.String {
		return raw, "", nil
	}
	r, ok := raw.(string)
	if ok {
		return nil, r, nil
	}
	b, err := json.Marshal(raw)
	if err != nil {
		return nil, "", fmt.Errorf("getOntId, json.Marshal error: %s", err)
	}
	ontIdObject := new(OntIdObject)
	err = json.Unmarshal(b, ontIdObject)
	if err != nil {
		return nil, "", fmt.Errorf("getOntId, json.Unmarshal error: %s", err)
	}
	m := make(map[string]interface{})
	if err := json.Unmarshal(b, &m); err == nil {
		return nil, "", fmt.Errorf("getOntId, json.Unmarshal result error: %s", err)
	}
	delete(m, "id")
	var result interface{}
	mb, err := json.Marshal(m)
	if err != nil {
		return nil, "", fmt.Errorf("getOntId, json.Marshal map error: %s", err)
	}
	err = json.Unmarshal(mb, &result)
	if err != nil {
		return nil, "", fmt.Errorf("getOntId, json.Unmarshal result error: %s", err)
	}
	return result, ontIdObject.Id, nil
}

func (this *Credential) createProof(ontId string, signer *Account, challenge string, domain interface{}, now int64) (*Proof, error) {
	issuanceDate := time.Unix(now, 0).UTC().Format("2006-01-02T15:04:05Z")
	// get public key id
	_, pkInfo, err := this.GetPublicKeyId(ontId, hex.EncodeToString(keypair.SerializePublicKey(signer.GetPublicKey())))
	if err != nil {
		return nil, fmt.Errorf("createProof, this.GetPublicKeyId error: %s", err)
	}
	proof := &Proof{
		Type:               pkInfo.Type,
		Created:            issuanceDate,
		Challenge:          challenge,
		Domain:             domain,
		ProofPurpose:       PROOF_PURPOSE,
		VerificationMethod: pkInfo.Id,
	}
	return proof, nil
}

func GenRequestMsg(request *Request) ([]byte, error) {
	sign := request.Proof.Hex
	request.Proof.Hex = ""
	msg, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("GenRequestMsg, json.Marshal error: %s", err)
	}
	request.Proof.Hex = sign
	return msg, nil
}

func GenCredentialMsg(credentials *VerifiableCredential) ([]byte, error) {
	sign := credentials.Proof.Hex
	credentials.Proof.Hex = ""
	msg, err := json.Marshal(credentials)
	if err != nil {
		return nil, fmt.Errorf("GenCredentialsMsg, json.Marshal error: %s", err)
	}
	credentials.Proof.Hex = sign
	return msg, nil
}

func GenPresentationMsg(presentation *VerifiablePresentation) ([]byte, error) {
	var signs []string
	for i := range presentation.Proof {
		signs = append(signs, presentation.Proof[i].Hex)
		presentation.Proof[i].Hex = ""
	}
	msg, err := json.Marshal(presentation)
	if err != nil {
		return nil, fmt.Errorf("GenPresentationMsg, json.Marshal error: %s", err)
	}
	for i := range presentation.Proof {
		presentation.Proof[i].Hex = signs[i]
	}
	return msg, nil
}
