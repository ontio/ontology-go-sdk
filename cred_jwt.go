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

type JWTCredential struct {
	Header  *Header  `json:"header"`
	Payload *Payload `json:"payload"`
	Jws     string   `json:"jws"`
}

func (this *Credential) CreateJWTCredential(contexts []string, types []string, credentialSubject interface{}, issuerId interface{},
	expirationDateTimestamp int64, challenge string, domain interface{}, signer *Account) (string, error) {
	is, ontId, err := getOntId(issuerId)
	if err != nil {
		return "", fmt.Errorf("CreateJWTCredential, getOntId error: %s", err)
	}
	// get public key id
	_, pkInfo, err := this.GetPublicKeyId(ontId, hex.EncodeToString(keypair.SerializePublicKey(signer.GetPublicKey())))
	if err != nil {
		return "", fmt.Errorf("CreateJWTCredential, this.GetPublicKeyId error: %s", err)
	}
	header := &Header{
		Alg: JWTSignType[pkInfo.Type],
		Typ: HEADER_TYPE,
		Kid: pkInfo.Id,
	}

	t := reflect.TypeOf(credentialSubject).Kind()
	if t != reflect.Struct && t != reflect.String {
		return "", fmt.Errorf("CreateJWTCredential, credentialSubject is not string or struct")
	}
	cs, sub, err := getOntId(credentialSubject)
	if err != nil {
		return "", fmt.Errorf("CreateJWTCredential, getOntId error: %s", err)
	}
	now := time.Now().Unix()
	proof, err := this.createProof(ontId, signer, challenge, domain, now)
	if err != nil {
		return "", fmt.Errorf("CreateJWTCredential, this.CreateProof error: %s", err)
	}
	proof.VerificationMethod = ""
	proof.Type = ""
	vc := &VC{
		Context:           append(DefaultContext, contexts...),
		Type:              append(DefaultCredentialType, types...),
		Issuer:            is,
		CredentialSubject: cs,
		CredentialStatus: &CredentialStatus{
			Id:   this.credRecordContractAddress.ToHexString(),
			Type: CREDENTIAL_STATUS_TYPE,
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

	credential := &JWTCredential{
		Header:  header,
		Payload: payload,
	}
	signData, err := credential.SignData()
	if err != nil {
		return "", fmt.Errorf("CreateJWTCredential, credential.SignData error: %s", err)
	}
	sign, err := signer.Sign(signData)
	if err != nil {
		return "", fmt.Errorf("CreateJWTCredential, signer.Sign error: %s", err)
	}
	credential.Jws = base64.StdEncoding.EncodeToString(sign)
	return credential.ToString()
}

func (this *Credential) VerifyJWTCredibleOntId(credibleOntIds []string, credential string) error {
	JWTCredential := new(JWTCredential)
	err := JWTCredential.Deserialization(credential)
	if err != nil {
		return fmt.Errorf("VerifyJWTCredibleOntId, JWTCredential.Deserialization error: %s", err)
	}

	for _, v := range credibleOntIds {
		if JWTCredential.Payload.Iss == v {
			return nil
		}
	}
	return fmt.Errorf("VerifyJWTCredibleOntId failed")
}

func (this *Credential) VerifyJWTDate(credential string) error {
	JWTCredential := new(JWTCredential)
	err := JWTCredential.Deserialization(credential)
	if err != nil {
		return fmt.Errorf("VerifyJWTDate, JWTCredential.Deserialization error: %s", err)
	}

	now := time.Now()
	if JWTCredential.Payload.Exp != 0 {
		if now.Unix() > JWTCredential.Payload.Exp {
			return fmt.Errorf("VerifyJWTDate expirationDate failed")
		}
	}

	if JWTCredential.Payload.Nbf != 0 {
		if now.Unix() < JWTCredential.Payload.Nbf {
			return fmt.Errorf("VerifyJWTDate issuanceDate nbf failed")
		}
	}
	if JWTCredential.Payload.Iat != 0 {
		if now.Unix() < JWTCredential.Payload.Iat {
			return fmt.Errorf("VerifyJWTDate issuanceDate iat failed")
		}
	}
	return nil
}

func (this *Credential) VerifyJWTIssuerSignature(credential string) error {
	JWTCredential := new(JWTCredential)
	err := JWTCredential.Deserialization(credential)
	if err != nil {
		return fmt.Errorf("VerifyJWTIssuerSignature, JWTCredential.Deserialization error: %s", err)
	}

	msg, err := JWTCredential.SignData()
	if err != nil {
		return fmt.Errorf("VerifyJWTIssuerSignature, JWTCredential.SignData error: %s", err)
	}
	err = this.verifyJWSProof(JWTCredential.Payload.Iss, JWTCredential.Payload.VC.Proof, msg, JWTCredential.Jws)
	if err != nil {
		return fmt.Errorf("VerifyJWTIssuerSignature, this.VerifyJWSProof error: %s", err)
	}
	return nil
}

func (this *Credential) verifyJWSProof(ontId string, proof *Proof, msg []byte, jws string) error {
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

func (this *Credential) VerifyJWTStatus(credential string) error {
	JWTCredential := new(JWTCredential)
	err := JWTCredential.Deserialization(credential)
	if err != nil {
		return fmt.Errorf("VerifyJWTStatus, JWTCredential.Deserialization error: %s", err)
	}

	if JWTCredential.Payload.VC.CredentialStatus.Type != CREDENTIAL_STATUS_TYPE {
		return fmt.Errorf("VerifyJWTStatus, credential status  %s not match", JWTCredential.Payload.VC.CredentialStatus.Type)
	}
	contractAddress, err := common.AddressFromHexString(JWTCredential.Payload.VC.CredentialStatus.Id)
	if err != nil {
		return fmt.Errorf("VerifyJWTStatus, common.AddressFromHexString error: %s", err)
	}
	status, err := this.getCredentialStatus(contractAddress, JWTCredential.Payload.Jti)
	if err != nil {
		return fmt.Errorf("VerifyJWTStatus, this.GetCredentialStatus error: %s", err)
	}
	if status != 1 {
		return fmt.Errorf("VerifyJWTStatus failed")
	}
	return nil
}

func (this *Credential) RevokeJWTCredentialByHolder(gasPrice, gasLimit uint64, credential string, holder string,
	signer, payer *Account) (common.Uint256, error) {
	JWTCredential := new(JWTCredential)
	err := JWTCredential.Deserialization(credential)
	if err != nil {
		return common.UINT256_EMPTY, fmt.Errorf("RevokeJWTCredentialByHolder, JWTCredential.Deserialization error: %s", err)
	}
	if JWTCredential.Payload.VC.CredentialStatus.Type != CREDENTIAL_STATUS_TYPE {
		return common.UINT256_EMPTY, fmt.Errorf("RevokeJWTCredentialByHolder, credential status  %s not match", JWTCredential.Payload.VC.CredentialStatus.Type)
	}
	contractAddress, err := common.AddressFromHexString(JWTCredential.Payload.VC.CredentialStatus.Id)
	if err != nil {
		return common.UINT256_EMPTY, fmt.Errorf("RevokeJWTCredentialByHolder, common.AddressFromHexString error: %s", err)
	}

	index, _, err := this.GetPublicKeyId(holder, hex.EncodeToString(keypair.SerializePublicKey(signer.GetPublicKey())))
	if err != nil {
		return common.UINT256_EMPTY, fmt.Errorf("RevokeJWTCredentialByHolder, this.GetPublicKeyId error: %s", err)
	}

	return this.revokeCredential(contractAddress, gasPrice, gasLimit, JWTCredential.Payload.Jti, holder, index, signer, payer)
}

func (this *Credential) RemoveJWTCredential(gasPrice, gasLimit uint64, credential string, holder string,
	signer, payer *Account) (common.Uint256, error) {
	JWTCredential := new(JWTCredential)
	err := JWTCredential.Deserialization(credential)
	if err != nil {
		return common.UINT256_EMPTY, fmt.Errorf("RemoveJWTCredential, JWTCredential.Deserialization error: %s", err)
	}

	index, _, err := this.GetPublicKeyId(holder, hex.EncodeToString(keypair.SerializePublicKey(signer.GetPublicKey())))
	if err != nil {
		return common.UINT256_EMPTY, fmt.Errorf("RemoveJWTCredential, this.GetPublicKeyId error: %s", err)
	}
	if JWTCredential.Payload.VC.CredentialStatus.Type != CREDENTIAL_STATUS_TYPE {
		return common.UINT256_EMPTY, fmt.Errorf("RemoveJWTCredential, credential status  %s not match", JWTCredential.Payload.VC.CredentialStatus.Type)
	}
	contractAddress, err := common.AddressFromHexString(JWTCredential.Payload.VC.CredentialStatus.Id)
	if err != nil {
		return common.UINT256_EMPTY, fmt.Errorf("RemoveJWTCredential, common.AddressFromHexString error: %s", err)
	}
	params := []interface{}{"Remove", []interface{}{JWTCredential.Payload.Jti, holder, index}}
	txHash, err := this.ontSdk.NeoVM.InvokeNeoVMContract(gasPrice, gasLimit, payer, signer, contractAddress, params)
	if err != nil {
		return common.UINT256_EMPTY, fmt.Errorf("RemoveJWTCredential, this.ontSdk.NeoVM.InvokeNeoVMContract error: %s", err)
	}
	return txHash, nil
}

func (this *Credential) CreateJWTPresentation(credentials []string, contexts, types []string, holder interface{},
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
	// check credentials
	for _, v := range credentials {
		JWTCredential := new(JWTCredential)
		err := JWTCredential.Deserialization(v)
		if err != nil {
			return "", fmt.Errorf("CreateJWTPresentation, JWTCredential.Deserialization error: %s", err)
		}
	}
	vp := &VP{
		Context:              append(DefaultContext, contexts...),
		Type:                 append(DefaultCredentialType, types...),
		VerifiableCredential: credentials,
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

	presentation := &JWTCredential{
		Header:  header,
		Payload: payload,
	}
	signData, err := presentation.SignData()
	if err != nil {
		return "", fmt.Errorf("CreateJWTPresentation, presentation.SignData error: %s", err)
	}
	sign, err := signer.Sign(signData)
	if err != nil {
		return "", fmt.Errorf("CreateJWTPresentation, signer.Sign error: %s", err)
	}
	presentation.Jws = base64.StdEncoding.EncodeToString(sign)
	return presentation.ToString()
}

func (this *Credential) JWTCred2Json(credential string) (*VerifiableCredential, error) {
	JWTCredential := new(JWTCredential)
	err := JWTCredential.Deserialization(credential)
	if err != nil {
		return nil, fmt.Errorf("JWTCred2Json, JWTCredential.Deserialization error: %s", err)
	}

	return nil, nil
}

func (cred *JWTCredential) ToString() (string, error) {
	headerb, err := json.Marshal(cred.Header)
	if err != nil {
		return "", fmt.Errorf("SignData, json.Marshal header error: %s", err)
	}
	headerString := base64.StdEncoding.EncodeToString(headerb)

	payloadb, err := json.Marshal(cred.Payload)
	if err != nil {
		return "", fmt.Errorf("SignData, json.Marshal payload error: %s", err)
	}
	payloadString := base64.StdEncoding.EncodeToString(payloadb)

	return headerString + "." + payloadString + "." + cred.Jws, nil
}

func (cred *JWTCredential) SignData() ([]byte, error) {
	headerb, err := json.Marshal(cred.Header)
	if err != nil {
		return nil, fmt.Errorf("SignData, json.Marshal header error: %s", err)
	}
	headerString := base64.StdEncoding.EncodeToString(headerb)

	payloadb, err := json.Marshal(cred.Payload)
	if err != nil {
		return nil, fmt.Errorf("SignData, json.Marshal payload error: %s", err)
	}
	payloadString := base64.StdEncoding.EncodeToString(payloadb)

	signData := headerString + "." + payloadString
	return []byte(signData), nil
}

func (cred *JWTCredential) Deserialization(jwt string) error {
	slice := strings.Split(jwt, ".")
	if len(slice) != 3 {
		return fmt.Errorf("JWTCredential Deserialization, length of elem is not 3")
	}
	headerb, err := base64.StdEncoding.DecodeString(slice[0])
	if err != nil {
		return fmt.Errorf("JWTCredential Deserialization, base64.StdEncoding.DecodeString header error: %s", err)
	}
	err = json.Unmarshal(headerb, cred.Header)
	if err != nil {
		return fmt.Errorf("JWTCredential Deserialization, json.Unmarshal header error: %s", err)
	}

	payloadb, err := base64.StdEncoding.DecodeString(slice[1])
	if err != nil {
		return fmt.Errorf("JWTCredential Deserialization, base64.StdEncoding.DecodeString payload error: %s", err)
	}
	err = json.Unmarshal(payloadb, cred.Payload)
	if err != nil {
		return fmt.Errorf("JWTCredential Deserialization, json.Unmarshal payload error: %s", err)
	}

	cred.Jws = slice[2]
	return nil
}
