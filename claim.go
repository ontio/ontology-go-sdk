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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/ontio/ontology-crypto/keypair"
	"github.com/ontio/ontology/common"
	"github.com/ontio/ontology/core/signature"
)

const (
	CLAIM_STATUS_TYPE    ClaimStatusType    = "ClaimContract"
	PROOF_SIGNATURE_TYPE ProofSignatureType = "EcdsaSecp256r1Signature2019"
	PROOF_PURPOSE        ProofPurpose       = "assertionMethod"
)

type ClaimStatusType string
type ProofSignatureType string
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
	Type               ProofSignatureType `json:"type,omitempty"`
	Created            string             `json:"created,omitempty"`
	ProofPurpose       ProofPurpose       `json:"proofPurpose,omitempty"`
	VerificationMethod string             `json:"verificationMethod,omitempty"`
	Hex                string             `json:"hex,omitempty"`
	Jws                string             `json:"jws,omitempty"`
}

type VerifiableCredential struct {
	Context           []string          `json:"@context,omitempty"`
	Id                string            `json:"id,omitempty"`
	Type              []string          `json:"type,omitempty"`
	Issuer            string            `json:"issuer,omitempty"`
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
	Holder               string                  `json:"holder,omitempty"`
	Proof                []*Proof                `json:"proof,omitempty"`
}

type PublicKeyList []*PublicKey

type PublicKey struct {
	Id           string `json:"id"`
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
	msg, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("GenSignReq, json.Marshal error: %s", err)
	}

	sig, err := signer.Sign(msg)
	if err != nil {
		return nil, fmt.Errorf("GenSignReq, signer.Sign error: %s", err)
	}
	issuanceDate := time.Unix(time.Now().Unix(), 0).Format("2006-01-02T15:04:05Z")
	proof := &Proof{
		Type:         PROOF_SIGNATURE_TYPE,
		Created:      issuanceDate,
		ProofPurpose: PROOF_PURPOSE,
		Hex:          hex.EncodeToString(sig),
	}
	request.Proof = proof

	return request, nil
}

func (this *Claim) VerifySignReq(request *Request) error {
	rawRequest := &Request{
		CredentialSubject: request.CredentialSubject,
		OntId:             request.OntId,
	}
	msg, err := json.Marshal(rawRequest)
	if err != nil {
		return fmt.Errorf("VerifySignReq, json.Marshal error: %s", err)
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

func (this *Claim) CreateClaim(contexts []string, types []string, credentialSubject interface{}, issuerId string,
	expirationDateTimestamp int64, signer *Account) (*VerifiableCredential, error) {
	claim := new(VerifiableCredential)

	claim.Context = append(DefaultContext, contexts...)
	claim.Type = append(DefaultClaimType, types...)
	claim.Issuer = issuerId

	issuanceDate := time.Unix(time.Now().Unix(), 0).Format("2006-01-02T15:04:05Z")
	claim.IssuanceDate = issuanceDate

	expirationDate := time.Unix(expirationDateTimestamp, 0).Format("2006-01-02T15:04:05Z")
	claim.ExpirationDate = expirationDate

	claim.CredentialSubject = credentialSubject

	credentialStatus := &CredentialStatus{
		Id:   this.claimContractAddress.ToHexString(),
		Type: CLAIM_STATUS_TYPE,
	}
	claim.CredentialStatus = credentialStatus

	// create proof
	proof := &Proof{
		Type:         PROOF_SIGNATURE_TYPE,
		Created:      issuanceDate,
		ProofPurpose: PROOF_PURPOSE,
	}

	// get public key id
	_, verificationMethod, err := this.GetPublicKeyId(issuerId, hex.EncodeToString(keypair.SerializePublicKey(signer.GetPublicKey())))
	if err != nil {
		return nil, fmt.Errorf("CreateClaim, this.GetPublicKeyId error: %s", err)
	}
	proof.VerificationMethod = verificationMethod

	msg, err := json.Marshal(claim)
	if err != nil {
		return nil, fmt.Errorf("CreateClaim, json.Marshal claim error: %s", err)
	}
	sig, err := signer.Sign(msg)
	if err != nil {
		return nil, fmt.Errorf("CreateClaim, signer.Sign error: %s", err)
	}
	proof.Hex = hex.EncodeToString(sig)

	claim.Proof = proof
	msg, err = json.Marshal(claim)
	if err != nil {
		return nil, fmt.Errorf("CreateClaim, json.Marshal claim with proof error: %s", err)
	}
	hash := sha256.Sum256(msg)
	claim.Id = hex.EncodeToString(hash[:])

	return claim, nil
}

func (this *Claim) GetPublicKeyId(ontId string, publicKeyHex string) (uint32, string, error) {
	publicKeyList, err := this.GetPublicKeyList(ontId)
	if err != nil {
		return 0, "", fmt.Errorf("GetPublicKeyId, this.GetPublicKeyList error: %s", err)
	}

	for i, v := range publicKeyList {
		if v.PublicKeyHex == publicKeyHex {
			return uint32(i + 1), v.Id, nil
		}
	}
	return 0, "", fmt.Errorf("GetPublicKeyId, record not found")
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

func (this *Claim) VerifyNotExpired(claim *VerifiableCredential) error {
	now := time.Now()
	expirationDate, err := time.Parse("2006-01-02T15:04:05Z", claim.ExpirationDate)
	if err != nil {
		return fmt.Errorf("VerifyNotExpired error: %s", err)
	}
	if now.After(expirationDate) {
		return fmt.Errorf("VerifyNotExpired failed")
	}
	return nil
}

func (this *Claim) VerifyIssuerSignature(claim *VerifiableCredential) error {
	raw := &VerifiableCredential{
		Context:           claim.Context,
		Type:              claim.Type,
		Issuer:            claim.Issuer,
		IssuanceDate:      claim.IssuanceDate,
		ExpirationDate:    claim.ExpirationDate,
		CredentialSubject: claim.CredentialSubject,
		CredentialStatus:  claim.CredentialStatus,
	}
	msg, err := json.Marshal(raw)
	if err != nil {
		return fmt.Errorf("VerifyIssuerSignature, json.Marshal raw error: %s", err)
	}

	err = this.VerifyProof(claim.Issuer, claim.Proof, msg)
	if err != nil {
		return fmt.Errorf("VerifyIssuerSignature, this.VerifyProof error: %s", err)
	}
	return nil
}

func (this *Claim) VerifyStatus(claim *VerifiableCredential) error {
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
	signerOntIds []string, signers []*Account) (*Presentation, error) {
	presentation := new(Presentation)
	presentation.Context = append(DefaultContext, contexts...)
	presentation.Type = append(DefaultPresentationType, types...)
	presentation.Holder = holder
	presentation.VerifiableCredential = claims

	msg, err := json.Marshal(presentation)
	if err != nil {
		return nil, fmt.Errorf("CreatePresentation, json.Marshal msg error: %s", err)
	}

	issuanceDate := time.Unix(time.Now().Unix(), 0).Format("2006-01-02T15:04:05Z")
	for i := range signerOntIds {
		// create proof
		proof := &Proof{
			Type:         PROOF_SIGNATURE_TYPE,
			Created:      issuanceDate,
			ProofPurpose: PROOF_PURPOSE,
		}

		// get public key id
		_, verificationMethod, err := this.GetPublicKeyId(signerOntIds[i], hex.EncodeToString(keypair.SerializePublicKey(signers[i].GetPublicKey())))
		if err != nil {
			return nil, fmt.Errorf("CreatePresentation, this.GetPublicKeyId error: %s", err)
		}
		proof.VerificationMethod = verificationMethod

		sign, err := signers[i].Sign(msg)
		if err != nil {
			return nil, fmt.Errorf("CreatePresentation, signers %d Sign error: %s", i, err)
		}
		proof.Hex = hex.EncodeToString(sign)
		presentation.Proof = append(presentation.Proof, proof)
	}

	msg, err = json.Marshal(presentation)
	if err != nil {
		return nil, fmt.Errorf("CreatePresentation, json.Marshal presentation with proof error: %s", err)
	}
	hash := sha256.Sum256(msg)
	presentation.Id = hex.EncodeToString(hash[:])
	return presentation, nil
}

func (this *Claim) VerifyPresentationProof(presentation *Presentation, index int) (string, error) {
	raw := &Presentation{
		Context:              presentation.Context,
		Type:                 presentation.Type,
		VerifiableCredential: presentation.VerifiableCredential,
		Holder:               presentation.Holder,
	}
	msg, err := json.Marshal(raw)
	if err != nil {
		return "", fmt.Errorf("VerifyPresentationProof, json.Marshal raw error: %s", err)
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
