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
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/ontio/ontology/core/signature"
	"reflect"
	"strings"
	"time"

	"github.com/ontio/ontology-crypto/keypair"
	"github.com/ontio/ontology/common"
	uuid "github.com/satori/go.uuid"
)

const (
	HEADER_TYPE = "JWT"
)

var JWTSignType = map[string]string{
	"EcdsaSecp224r1VerificationKey2019": "ES224",
	"EcdsaSecp256r1VerificationKey2019": "ES256",
	"EcdsaSecp384r1VerificationKey2019": "ES384",
	"EcdsaSecp521r1VerificationKey2019": "ES512",
	"EcdsaSecp256k1VerificationKey2019": "ES256K",
	"Ed25519VerificationKey2018":        "EdDSA",
	"SM2VerificationKey2019":            "SM",
}

type VerifiableCredentialJWT struct {
	Header    Header
	Payload   Payload
	Signature []byte
}

type Header struct {
	Alg string `json:"alg,omitempty"`
	Typ string `json:"typ,omitempty"`
	Kid string `json:"kid,omitempty"`
}

type VC struct {
	Context           []string          `json:"@context,omitempty"`
	Type              []string          `json:"type,omitempty"`
	Issuer            interface{}       `json:"issuer,omitempty"`
	CredentialSubject interface{}       `json:"credentialSubject,omitempty"`
	CredentialStatus  *CredentialStatus `json:"credentialStatus,omitempty"`
	Proof             *Proof            `json:"proof,omitempty"`
}

type VP struct {
	Context              []string    `json:"@context,omitempty"`
	Type                 []string    `json:"type,omitempty"`
	VerifiableCredential []string    `json:"credentialStatus,omitempty"`
	Holder               interface{} `json:"holder,omitempty"`
	Proof                *Proof      `json:"proof,omitempty"`
}

type Payload struct {
	Iss   string      `json:"iss,omitempty"`
	Sub   string      `json:"sub,omitempty"`
	Aud   interface{} `json:"aud,omitempty"`
	Exp   int64       `json:"exp,omitempty"`
	Nbf   int64       `json:"nbf,omitempty"`
	Iat   int64       `json:"iat,omitempty"`
	Jti   string      `json:"jti,omitempty"`
	Nonce string      `json:"nonce,omitempty"`
	VC    *VC         `json:"vc,omitempty"`
	VP    *VP         `json:"vp,omitempty"`
}

type JWTClaim struct {
	Header  *Header  `json:"header"`
	Payload *Payload `json:"payload"`
	Jws     string   `json:"jws"`
}

func (this *Claim) CreateJWTClaim(contexts []string, types []string, credentialSubject interface{}, issuerId interface{},
	expirationDateTimestamp int64, challenge string, domain interface{}, signer *Account) (string, error) {
	is, ontId, err := getOntId(issuerId)
	if err != nil {
		return "", fmt.Errorf("CreateJWTClaim, getOntId error: %s", err)
	}
	// get public key id
	_, pkInfo, err := this.GetPublicKeyId(ontId, hex.EncodeToString(keypair.SerializePublicKey(signer.GetPublicKey())))
	if err != nil {
		return "", fmt.Errorf("CreateJWTClaim, this.GetPublicKeyId error: %s", err)
	}
	header := &Header{
		Alg: JWTSignType[pkInfo.Type],
		Typ: HEADER_TYPE,
		Kid: pkInfo.Id,
	}

	t := reflect.TypeOf(credentialSubject).Kind()
	if t != reflect.Struct && t != reflect.String {
		return "", fmt.Errorf("CreateJWTClaim, credentialSubject is not string or struct")
	}
	cs, sub, err := getOntId(credentialSubject)
	if err != nil {
		return "", fmt.Errorf("CreateJWTClaim, getOntId error: %s", err)
	}
	now := time.Now().Unix()
	proof, err := this.createProof(ontId, signer, challenge, domain, now)
	if err != nil {
		return "", fmt.Errorf("CreateClaim, this.CreateProof error: %s", err)
	}
	proof.VerificationMethod = ""
	proof.Type = ""
	vc := &VC{
		Context:           append(DefaultContext, contexts...),
		Type:              append(DefaultClaimType, types...),
		Issuer:            is,
		CredentialSubject: cs,
		CredentialStatus: &CredentialStatus{
			Id:   this.claimContractAddress.ToHexString(),
			Type: CLAIM_STATUS_TYPE,
		},
		Proof: proof,
	}
	payload := &Payload{
		Sub: sub,
		Jti: UUID_PREFIX + uuid.NewV4().String(),
		Iss: ontId,
		Nbf: now,
		Iat: now,
		VC:  vc,
	}
	if expirationDateTimestamp != 0 {
		payload.Exp = expirationDateTimestamp
	}

	claim := &JWTClaim{
		Header:  header,
		Payload: payload,
	}
	signData, err := claim.SignData()
	if err != nil {
		return "", fmt.Errorf("CreateJWTClaim, claim.SignData error: %s", err)
	}
	sign, err := signer.Sign(signData)
	if err != nil {
		return "", fmt.Errorf("CreateJWTClaim, signer.Sign error: %s", err)
	}
	claim.Jws = base64.StdEncoding.EncodeToString(sign)
	return claim.ToString()
}

func (this *Claim) VerifyJWTCredibleOntId(credibleOntIds []string, claim string) error {
	JWTClaim := new(JWTClaim)
	err := JWTClaim.Deserialization(claim)
	if err != nil {
		return fmt.Errorf("VerifyJWTCredibleOntId, JWTClaim.Deserialization error: %s", err)
	}

	for _, v := range credibleOntIds {
		if JWTClaim.Payload.Iss == v {
			return nil
		}
	}
	return fmt.Errorf("VerifyJWTCredibleOntId failed")
}

func (this *Claim) VerifyJWTDate(claim string) error {
	JWTClaim := new(JWTClaim)
	err := JWTClaim.Deserialization(claim)
	if err != nil {
		return fmt.Errorf("VerifyJWTDate, JWTClaim.Deserialization error: %s", err)
	}

	now := time.Now()
	if JWTClaim.Payload.Exp != 0 {
		if now.Unix() > JWTClaim.Payload.Exp {
			return fmt.Errorf("VerifyJWTDate expirationDate failed")
		}
	}

	if JWTClaim.Payload.Nbf != 0 {
		if now.Unix() < JWTClaim.Payload.Nbf {
			return fmt.Errorf("VerifyJWTDate issuanceDate nbf failed")
		}
	}
	if JWTClaim.Payload.Iat != 0 {
		if now.Unix() < JWTClaim.Payload.Iat {
			return fmt.Errorf("VerifyJWTDate issuanceDate iat failed")
		}
	}
	return nil
}

func (this *Claim) VerifyJWTIssuerSignature(claim string) error {
	JWTClaim := new(JWTClaim)
	err := JWTClaim.Deserialization(claim)
	if err != nil {
		return fmt.Errorf("VerifyJWTIssuerSignature, JWTClaim.Deserialization error: %s", err)
	}

	msg, err := JWTClaim.SignData()
	if err != nil {
		return fmt.Errorf("VerifyJWTIssuerSignature, JWTClaim.SignData error: %s", err)
	}
	err = this.verifyJWSProof(JWTClaim.Payload.Iss, JWTClaim.Payload.VC.Proof, msg, JWTClaim.Jws)
	if err != nil {
		return fmt.Errorf("VerifyJWTIssuerSignature, this.VerifyJWSProof error: %s", err)
	}
	return nil
}

func (this *Claim) verifyJWSProof(ontId string, proof *Proof, msg []byte, jws string) error {
	sig, err := base64.StdEncoding.DecodeString(jws)
	if err != nil {
		return fmt.Errorf("VerifyJWSProof, base64.StdEncoding.DecodeString jws error: %s", err)
	}

	publicKeyHex, err := this.GetPublicKey(ontId, proof.VerificationMethod)
	if err != nil {
		return fmt.Errorf("VerifyJWSProof, this.GetPublicKey error: %s", err)
	}
	data, err := hex.DecodeString(publicKeyHex)
	if err != nil {
		return fmt.Errorf("VerifyJWSProof, hex.DecodeString public key error: %s", err)
	}
	pk, err := keypair.DeserializePublicKey(data)
	if err != nil {
		return fmt.Errorf("VerifyJWSProof, keypair.DeserializePublicKey error: %s", err)
	}

	return signature.Verify(pk, msg, sig)
}

func (this *Claim) VerifyJWTStatus(claim string) error {
	JWTClaim := new(JWTClaim)
	err := JWTClaim.Deserialization(claim)
	if err != nil {
		return fmt.Errorf("VerifyJWTStatus, JWTClaim.Deserialization error: %s", err)
	}

	if JWTClaim.Payload.VC.CredentialStatus.Type != CLAIM_STATUS_TYPE {
		return fmt.Errorf("VerifyJWTStatus, credential status  %s not match", JWTClaim.Payload.VC.CredentialStatus.Type)
	}
	contractAddress, err := common.AddressFromHexString(JWTClaim.Payload.VC.CredentialStatus.Id)
	if err != nil {
		return fmt.Errorf("VerifyJWTStatus, common.AddressFromHexString error: %s", err)
	}
	status, err := this.getClaimStatus(contractAddress, JWTClaim.Payload.Jti)
	if err != nil {
		return fmt.Errorf("VerifyJWTStatus, this.GetClaimStatus error: %s", err)
	}
	if status != 1 {
		return fmt.Errorf("VerifyJWTStatus failed")
	}
	return nil
}

func (this *Claim) RevokeJWTClaimByHolder(gasPrice, gasLimit uint64, claim string, holder string,
	signer, payer *Account) (common.Uint256, error) {
	JWTClaim := new(JWTClaim)
	err := JWTClaim.Deserialization(claim)
	if err != nil {
		return common.UINT256_EMPTY, fmt.Errorf("RevokeJWTClaimByHolder, JWTClaim.Deserialization error: %s", err)
	}
	if JWTClaim.Payload.VC.CredentialStatus.Type != CLAIM_STATUS_TYPE {
		return common.UINT256_EMPTY, fmt.Errorf("RevokeJWTClaimByHolder, credential status  %s not match", JWTClaim.Payload.VC.CredentialStatus.Type)
	}
	contractAddress, err := common.AddressFromHexString(JWTClaim.Payload.VC.CredentialStatus.Id)
	if err != nil {
		return common.UINT256_EMPTY, fmt.Errorf("RevokeJWTClaimByHolder, common.AddressFromHexString error: %s", err)
	}

	index, _, err := this.GetPublicKeyId(holder, hex.EncodeToString(keypair.SerializePublicKey(signer.GetPublicKey())))
	if err != nil {
		return common.UINT256_EMPTY, fmt.Errorf("RevokeJWTClaimByHolder, this.GetPublicKeyId error: %s", err)
	}

	return this.revokeClaim(contractAddress, gasPrice, gasLimit, JWTClaim.Payload.Jti, holder, index, signer, payer)
}

func (this *Claim) RemoveJWTClaim(gasPrice, gasLimit uint64, claim string, holder string,
	signer, payer *Account) (common.Uint256, error) {
	JWTClaim := new(JWTClaim)
	err := JWTClaim.Deserialization(claim)
	if err != nil {
		return common.UINT256_EMPTY, fmt.Errorf("RemoveJWTClaim, JWTClaim.Deserialization error: %s", err)
	}

	index, _, err := this.GetPublicKeyId(holder, hex.EncodeToString(keypair.SerializePublicKey(signer.GetPublicKey())))
	if err != nil {
		return common.UINT256_EMPTY, fmt.Errorf("RemoveJWTClaim, this.GetPublicKeyId error: %s", err)
	}
	if JWTClaim.Payload.VC.CredentialStatus.Type != CLAIM_STATUS_TYPE {
		return common.UINT256_EMPTY, fmt.Errorf("RemoveJWTClaim, credential status  %s not match", JWTClaim.Payload.VC.CredentialStatus.Type)
	}
	contractAddress, err := common.AddressFromHexString(JWTClaim.Payload.VC.CredentialStatus.Id)
	if err != nil {
		return common.UINT256_EMPTY, fmt.Errorf("RemoveJWTClaim, common.AddressFromHexString error: %s", err)
	}
	params := []interface{}{"Remove", []interface{}{JWTClaim.Payload.Jti, holder, index}}
	txHash, err := this.ontSdk.NeoVM.InvokeNeoVMContract(gasPrice, gasLimit, payer, signer, contractAddress, params)
	if err != nil {
		return common.UINT256_EMPTY, fmt.Errorf("RemoveJWTClaim, this.ontSdk.NeoVM.InvokeNeoVMContract error: %s", err)
	}
	return txHash, nil
}

func (this *Claim) CreateJWTPresentation(claims []string, contexts, types []string, holder interface{},
	nonce string, aud interface{}, signer *Account) (string, error) {
	hd, ontId, err := getOntId(holder)
	if err != nil {
		return "", fmt.Errorf("CreateJWTPresentation, getOntId error: %s", err)
	}
	// get public key id
	_, pkInfo, err := this.GetPublicKeyId(ontId, hex.EncodeToString(keypair.SerializePublicKey(signer.GetPublicKey())))
	if err != nil {
		return "", fmt.Errorf("CreateJWTPresentation, this.GetPublicKeyId error: %s", err)
	}
	header := &Header{
		Alg: JWTSignType[pkInfo.Type],
		Typ: HEADER_TYPE,
		Kid: pkInfo.Id,
	}

	now := time.Now().Unix()
	var domain interface{}
	proof, err := this.createProof(ontId, signer, "", domain, now)
	if err != nil {
		return "", fmt.Errorf("CreateJWTPresentation, this.CreateProof error: %s", err)
	}
	proof.VerificationMethod = ""
	proof.Type = ""
	// check claims
	for _, v := range claims {
		JWTClaim := new(JWTClaim)
		err := JWTClaim.Deserialization(v)
		if err != nil {
			return "", fmt.Errorf("CreateJWTPresentation, JWTClaim.Deserialization error: %s", err)
		}
	}
	vp := &VP{
		Context:              append(DefaultContext, contexts...),
		Type:                 append(DefaultClaimType, types...),
		VerifiableCredential: claims,
		Holder:               hd,
		Proof:                proof,
	}
	payload := &Payload{
		Aud:   aud,
		Nonce: nonce,
		Jti:   UUID_PREFIX + uuid.NewV4().String(),
		Iss:   ontId,
		VP:    vp,
	}

	presentation := &JWTClaim{
		Header:  header,
		Payload: payload,
	}
	signData, err := presentation.SignData()
	if err != nil {
		return "", fmt.Errorf("CreateJWTPresentation, claim.SignData error: %s", err)
	}
	sign, err := signer.Sign(signData)
	if err != nil {
		return "", fmt.Errorf("CreateJWTPresentation, signer.Sign error: %s", err)
	}
	presentation.Jws = base64.StdEncoding.EncodeToString(sign)
	return presentation.ToString()
}

func (this *Claim) JWTClaim2Json(claim string) (*VerifiableCredential, error) {

}

func (claim *JWTClaim) ToString() (string, error) {
	headerb, err := json.Marshal(claim.Header)
	if err != nil {
		return "", fmt.Errorf("SignData, json.Marshal header error: %s", err)
	}
	headerString := base64.StdEncoding.EncodeToString(headerb)

	payloadb, err := json.Marshal(claim.Payload)
	if err != nil {
		return "", fmt.Errorf("SignData, json.Marshal payload error: %s", err)
	}
	payloadString := base64.StdEncoding.EncodeToString(payloadb)

	return headerString + "." + payloadString + "." + claim.Jws, nil
}

func (claim *JWTClaim) SignData() ([]byte, error) {
	headerb, err := json.Marshal(claim.Header)
	if err != nil {
		return nil, fmt.Errorf("SignData, json.Marshal header error: %s", err)
	}
	headerString := base64.StdEncoding.EncodeToString(headerb)

	payloadb, err := json.Marshal(claim.Payload)
	if err != nil {
		return nil, fmt.Errorf("SignData, json.Marshal payload error: %s", err)
	}
	payloadString := base64.StdEncoding.EncodeToString(payloadb)

	signData := headerString + "." + payloadString
	return []byte(signData), nil
}

func (claim *JWTClaim) Deserialization(jwt string) error {
	slice := strings.Split(jwt, ".")
	if len(slice) != 3 {
		return fmt.Errorf("JWTClaim Deserialization, length of elem is not 3")
	}
	headerb, err := base64.StdEncoding.DecodeString(slice[0])
	if err != nil {
		return fmt.Errorf("JWTClaim Deserialization, base64.StdEncoding.DecodeString header error: %s", err)
	}
	err = json.Unmarshal(headerb, claim.Header)
	if err != nil {
		return fmt.Errorf("JWTClaim Deserialization, json.Unmarshal header error: %s", err)
	}

	payloadb, err := base64.StdEncoding.DecodeString(slice[1])
	if err != nil {
		return fmt.Errorf("JWTClaim Deserialization, base64.StdEncoding.DecodeString payload error: %s", err)
	}
	err = json.Unmarshal(payloadb, claim.Payload)
	if err != nil {
		return fmt.Errorf("JWTClaim Deserialization, json.Unmarshal payload error: %s", err)
	}

	claim.Jws = slice[2]
	return nil
}
