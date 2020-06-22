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
	"strings"
	"time"

	"github.com/ontio/ontology-crypto/keypair"
	"github.com/ontio/ontology/common"
	"github.com/ontio/ontology/core/signature"
	"github.com/satori/go.uuid"
)

const (
	CLAIM_STATUS_TYPE ClaimStatusType = "AttestContract"
	PROOF_PURPOSE     ProofPurpose    = "assertionMethod"
	UUID_PREFIX                       = "urn:uuid:"
)

type ClaimStatusType string
type ProofPurpose string

var DefaultContext = []string{"https://www.w3.org/2018/credentials/v1", "https://ontid.ont.io/credentials/v1"}
var DefaultClaimType = []string{"VerifiableCredential"}
var DefaultPresentationType = []string{"VerifiablePresentation"}

type Claim struct {
	claimContractAddress common.Address
	ontSdk               *OntologySdk
}

type Request struct {
	CredentialSubject interface{} `json:"credentialSubject,omitempty"`
	OntId             string      `json:"ontId,omitempty"`
	Proof             *Proof      `json:"proof,omitempty"`
}

type CredentialStatus struct {
	Id   string          `json:"id"`
	Type ClaimStatusType `json:"type"`
}

type Proof struct {
	Type               string       `json:"type,omitempty"`
	Created            string       `json:"created,omitempty"`
	Challenge          string       `json:"chanllege,omitempty"`
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

type Presentation struct {
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

func newClaim(ontSdk *OntologySdk) *Claim {
	return &Claim{
		ontSdk: ontSdk,
	}
}

func (this *Claim) GenSignReq(credentialSubject interface{}, ontId string, signer *Account) (*Request, error) {
	request := &Request{
		CredentialSubject: credentialSubject,
		OntId:             ontId,
	}
	proof, err := this.CreateProof(ontId, signer, "", "")
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

func (this *Claim) VerifySignReq(request *Request) error {
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

func (this *Claim) CreateClaim(contexts []string, types []string, credentialSubject interface{}, issuerId interface{},
	expirationDateTimestamp int64, challenge string, domain interface{}, signer *Account) (*VerifiableCredential, error) {
	claim := new(VerifiableCredential)
	claim.Id = UUID_PREFIX + uuid.NewV4().String()
	claim.Context = append(DefaultContext, contexts...)
	claim.Type = append(DefaultClaimType, types...)
	claim.Issuer = issuerId

	now := time.Now().Unix()
	issuanceDate := time.Unix(now, 0).Format("2006-01-02T15:04:05Z")
	claim.IssuanceDate = issuanceDate

	if expirationDateTimestamp != 0 {
		expirationDate := time.Unix(expirationDateTimestamp, 0).Format("2006-01-02T15:04:05Z")
		claim.ExpirationDate = expirationDate
		if now > expirationDateTimestamp {
			return nil, fmt.Errorf("CreateClaim, now is after expirationDateTimestamp")
		}
	}

	claim.CredentialSubject = credentialSubject

	credentialStatus := &CredentialStatus{
		Id:   this.claimContractAddress.ToHexString(),
		Type: CLAIM_STATUS_TYPE,
	}
	claim.CredentialStatus = credentialStatus

	// create proof
	_, ontId, err := getOntId(issuerId)
	if err != nil {
		return nil, fmt.Errorf("CreateClaim, getOntId error: %s", err)
	}
	proof, err := this.CreateProof(ontId, signer, challenge, domain)
	if err != nil {
		return nil, fmt.Errorf("CreateClaim, this.CreateProof error: %s", err)
	}
	claim.Proof = proof

	msg, err := json.Marshal(claim)
	if err != nil {
		return nil, fmt.Errorf("CreateClaim, json.Marshal claim error: %s", err)
	}
	sig, err := signer.Sign(msg)
	if err != nil {
		return nil, fmt.Errorf("CreateClaim, signer.Sign error: %s", err)
	}
	claim.Proof.Hex = hex.EncodeToString(sig)

	return claim, nil
}

func (this *Claim) GetPublicKeyId(ontId string, publicKeyHex string) (uint32, *PublicKey, error) {
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

func (this *Claim) GetPublicKey(ontId string, Id string) (string, error) {
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

func (this *Claim) GetPublicKeyList(ontId string) (PublicKeyList, error) {
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

func (this *Claim) CommitClaim(contractAddress common.Address, gasPrice, gasLimit uint64, claimId, issuerId,
	holderId string, signer, payer *Account) (common.Uint256, error) {
	index, _, err := this.GetPublicKeyId(holderId, hex.EncodeToString(keypair.SerializePublicKey(signer.GetPublicKey())))
	if err != nil {
		return common.UINT256_EMPTY, fmt.Errorf("CommitClaim, this.GetPublicKeyId error: %s", err)
	}
	params := []interface{}{"Commit", []interface{}{claimId, issuerId, index, holderId}}
	txHash, err := this.ontSdk.NeoVM.InvokeNeoVMContract(gasPrice, gasLimit, payer, signer, contractAddress, params)
	if err != nil {
		return common.UINT256_EMPTY, fmt.Errorf("CommitClaim, this.ontSdk.NeoVM.InvokeNeoVMContract error: %s", err)
	}
	return txHash, nil
}

func (this *Claim) RevokeClaim(contractAddress common.Address, gasPrice, gasLimit uint64, claimId, ontId string, index uint32,
	signer, payer *Account) (common.Uint256, error) {
	params := []interface{}{"Revoke", []interface{}{claimId, ontId, index}}
	txHash, err := this.ontSdk.NeoVM.InvokeNeoVMContract(gasPrice, gasLimit, payer, signer, contractAddress, params)
	if err != nil {
		return common.UINT256_EMPTY, fmt.Errorf("RevokeClaim, this.ontSdk.NeoVM.InvokeNeoVMContract error: %s", err)
	}
	return txHash, nil
}

func (this *Claim) RemoveClaim(gasPrice, gasLimit uint64, claim *VerifiableCredential, ontId string,
	signer, payer *Account) (common.Uint256, error) {
	index, _, err := this.GetPublicKeyId(ontId, hex.EncodeToString(keypair.SerializePublicKey(signer.GetPublicKey())))
	if err != nil {
		return common.UINT256_EMPTY, fmt.Errorf("RemoveClaim, this.GetPublicKeyId error: %s", err)
	}
	if claim.CredentialStatus.Type != CLAIM_STATUS_TYPE {
		return common.UINT256_EMPTY, fmt.Errorf("RemoveClaim, credential status  %s not match", claim.CredentialStatus.Type)
	}
	contractAddress, err := common.AddressFromHexString(claim.CredentialStatus.Id)
	if err != nil {
		return common.UINT256_EMPTY, fmt.Errorf("RemoveClaim, common.AddressFromHexString error: %s", err)
	}
	params := []interface{}{"Remove", []interface{}{claim.Id, ontId, index}}
	txHash, err := this.ontSdk.NeoVM.InvokeNeoVMContract(gasPrice, gasLimit, payer, signer, contractAddress, params)
	if err != nil {
		return common.UINT256_EMPTY, fmt.Errorf("RevokeClaim, this.ontSdk.NeoVM.InvokeNeoVMContract error: %s", err)
	}
	return txHash, nil
}

func (this *Claim) VerifyCredibleOntId(credibleOntIds []string, claim *VerifiableCredential) error {
	for _, v := range credibleOntIds {
		if claim.Issuer == v {
			return nil
		}
	}
	return fmt.Errorf("VerifyCredibleOntId failed")
}

func (this *Claim) VerifyDate(claim *VerifiableCredential) error {
	now := time.Now()
	expirationDate, err := time.ParseInLocation("2006-01-02T15:04:05Z", claim.ExpirationDate, time.Local)
	if err != nil {
		return fmt.Errorf("VerifyDate error: %s", err)
	}
	if now.Unix() > expirationDate.Unix() {
		return fmt.Errorf("VerifyDate expirationDate failed")
	}

	issuanceDate, err := time.ParseInLocation("2006-01-02T15:04:05Z", claim.IssuanceDate, time.Local)
	if err != nil {
		return fmt.Errorf("VerifyDate error: %s", err)
	}
	if now.Unix() < issuanceDate.Unix() {
		return fmt.Errorf("VerifyDate issuanceDate failed")
	}
	return nil
}

func (this *Claim) VerifyIssuerSignature(claim *VerifiableCredential) error {
	msg, err := GenClaimMsg(claim)
	if err != nil {
		return fmt.Errorf("VerifyIssuerSignature, GenClaimMsg error: %s", err)
	}
	_, ontId, err := getOntId(claim.Issuer)
	if err != nil {
		return fmt.Errorf("VerifyIssuerSignature, getOntId error: %s", err)
	}
	err = this.VerifyProof(ontId, claim.Proof, msg)
	if err != nil {
		return fmt.Errorf("VerifyIssuerSignature, this.VerifyProof error: %s", err)
	}
	return nil
}

func (this *Claim) VerifyStatus(claim *VerifiableCredential) error {
	if claim.CredentialStatus.Type != CLAIM_STATUS_TYPE {
		return fmt.Errorf("VerifyStatus, credential status  %s not match", claim.CredentialStatus.Type)
	}
	contractAddress, err := common.AddressFromHexString(claim.CredentialStatus.Id)
	if err != nil {
		return fmt.Errorf("VerifyStatus, common.AddressFromHexString error: %s", err)
	}
	status, err := this.GetClaimStatus(contractAddress, claim.Id)
	if err != nil {
		return fmt.Errorf("VerifyStatus, this.GetClaimStatus error: %s", err)
	}
	if status != 1 {
		return fmt.Errorf("VerifyStatus failed")
	}
	return nil
}

func (this *Claim) GetClaimStatus(contractAddress common.Address, claimId string) (uint64, error) {
	params := []interface{}{"GetStatus", []interface{}{claimId}}
	preExecResult, err := this.ontSdk.NeoVM.PreExecInvokeNeoVMContract(contractAddress, params)
	if err != nil {
		return 0, fmt.Errorf("GetClaimStatus, this.ontSdk.NeoVM.PreExecInvokeNeoVMContract error: %s", err)
	}
	r, err := preExecResult.Result.ToInteger()
	if err != nil {
		return 0, fmt.Errorf("GetClaimStatus, preExecResult.Result.ToInteger error: %s", err)
	}
	return r.Uint64(), nil
}

func (this *Claim) CreatePresentation(claims []*VerifiableCredential, contexts, types []string, holder string,
	signerOntIds, challenge []string, domain []interface{}, signers []*Account) (*Presentation, error) {
	presentation := new(Presentation)
	presentation.Id = UUID_PREFIX + uuid.NewV4().String()
	presentation.Context = append(DefaultContext, contexts...)
	presentation.Type = append(DefaultPresentationType, types...)
	presentation.Holder = holder
	presentation.VerifiableCredential = claims

	if !(len(signerOntIds) == len(challenge) && len(signerOntIds) == len(domain) && len(signerOntIds) == len(signers)) {
		return nil, fmt.Errorf("input params error")
	}

	for i := range signerOntIds {
		// create proof
		proof, err := this.CreateProof(signerOntIds[i], signers[i], challenge[i], domain[i])
		if err != nil {
			return nil, fmt.Errorf("CreatePresentation, this.CreateProof error: %s", err)
		}
		presentation.Proof = append(presentation.Proof, proof)
	}
	msg, err := json.Marshal(presentation)
	if err != nil {
		return nil, fmt.Errorf("CreatePresentation, json.Marshal msg error: %s", err)
	}
	for j := range signerOntIds {
		sig, err := signers[j].Sign(msg)
		if err != nil {
			return nil, fmt.Errorf("CreatePresentation, signer.Sign error: %s", err)
		}
		presentation.Proof[j].Hex = hex.EncodeToString(sig)
	}

	return presentation, nil
}

func (this *Claim) VerifyPresentationProof(presentation *Presentation, index int) (string, error) {
	msg, err := GenPresentationMsg(presentation)
	if err != nil {
		return "", fmt.Errorf("VerifyPresentationProof, GenPresentationMsg error: %s", err)
	}
	ontId := parseOntId(presentation.Proof[index].VerificationMethod)
	err = this.VerifyProof(ontId, presentation.Proof[index], msg)
	if err != nil {
		return "", fmt.Errorf("VerifyPresentationProof, this.VerifyProof error: %s", err)
	}
	return ontId, nil
}

func (this *Claim) VerifyProof(ontId string, proof *Proof, msg []byte) error {
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

func (this *Claim) RevokeClaimByHolder(gasPrice, gasLimit uint64, claim *VerifiableCredential, holder string,
	signer, payer *Account) (common.Uint256, error) {
	if claim.CredentialStatus.Type != CLAIM_STATUS_TYPE {
		return common.UINT256_EMPTY, fmt.Errorf("RevokeIdByHolder, credential status  %s not match", claim.CredentialStatus.Type)
	}
	contractAddress, err := common.AddressFromHexString(claim.CredentialStatus.Id)
	if err != nil {
		return common.UINT256_EMPTY, fmt.Errorf("RevokeIdByHolder, common.AddressFromHexString error: %s", err)
	}

	index, _, err := this.GetPublicKeyId(holder, hex.EncodeToString(keypair.SerializePublicKey(signer.GetPublicKey())))
	if err != nil {
		return common.UINT256_EMPTY, fmt.Errorf("RevokeIdByHolder, this.GetPublicKeyId error: %s", err)
	}

	return this.RevokeClaim(contractAddress, gasPrice, gasLimit, claim.Id, holder, index, signer, payer)
}

func (this *Claim) RevokeClaimByIssuer(gasPrice, gasLimit uint64, claimId string, issuer string,
	signer, payer *Account) (common.Uint256, error) {
	index, _, err := this.GetPublicKeyId(issuer, hex.EncodeToString(keypair.SerializePublicKey(signer.GetPublicKey())))
	if err != nil {
		return common.UINT256_EMPTY, fmt.Errorf("RevokeIdByIssuer, this.GetPublicKeyId error: %s", err)
	}

	return this.RevokeClaim(this.claimContractAddress, gasPrice, gasLimit, claimId, issuer, index, signer, payer)
}

func parseOntId(raw string) string {
	return strings.Split(raw, "#")[0]
}

type OntIdObject struct {
	Id string `json:"id"`
}

func getOntId(raw interface{}) (map[string]interface{}, string, error) {
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
	var result map[string]interface{}
	if err := json.Unmarshal(b, &result); err == nil {
		return nil, "", fmt.Errorf("getOntId, json.Unmarshal result error: %s", err)
	}
	delete(result, "id")
	return result, ontIdObject.Id, nil
}

func (this *Claim) CreateProof(ontId string, signer *Account, challenge string, domain interface{}) (*Proof, error) {
	issuanceDate := time.Unix(time.Now().Unix(), 0).Format("2006-01-02T15:04:05Z")
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

func GenClaimMsg(claim *VerifiableCredential) ([]byte, error) {
	sign := claim.Proof.Hex
	claim.Proof.Hex = ""
	msg, err := json.Marshal(claim)
	if err != nil {
		return nil, fmt.Errorf("GenClaimMsg, json.Marshal error: %s", err)
	}
	claim.Proof.Hex = sign
	return msg, nil
}

func GenPresentationMsg(presentation *Presentation) ([]byte, error) {
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
