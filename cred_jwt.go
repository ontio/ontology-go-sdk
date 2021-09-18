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
	"strings"
	"time"

	"github.com/ontio/ontology-crypto/keypair"
	"github.com/ontio/ontology/common"
	"github.com/ontio/ontology/core/signature"
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

var JsonSignType = map[string]string{
	"ES224":  "EcdsaSecp224r1VerificationKey2019",
	"ES256":  "EcdsaSecp256r1VerificationKey2019",
	"ES384":  "EcdsaSecp384r1VerificationKey2019",
	"ES512":  "EcdsaSecp521r1VerificationKey2019",
	"ES256K": "EcdsaSecp256k1VerificationKey2019",
	"EdDSA":  "Ed25519VerificationKey2018",
	"SM":     "SM2VerificationKey2019",
}

type VerifiableCredentialJWT struct {
	Header    Header
	Payload   Payload
	Signature []byte
}

type Header struct {
	Alg string `json:"alg,omitempty"`
	Kid string `json:"kid,omitempty"`
	Typ string `json:"typ,omitempty"`
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
	VerifiableCredential []string    `json:"verifiableCredential,omitempty"`
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
	header, err := makeJWTHeader(pkInfo.Type, pkInfo.Id)
	if err != nil {
		return "", fmt.Errorf("CreateJWTCredential, makeJWTHeader error: %s", err)
	}

	cs, sub, err := getOntId(credentialSubject)
	if err != nil {
		return "", fmt.Errorf("CreateJWTCredential, getOntId error: %s", err)
	}

	now := time.Now().UTC().Unix()
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
	JWTCredential, err := DeserializeJWT(credential)
	if err != nil {
		return fmt.Errorf("VerifyJWTCredibleOntId, DeserializeJWT error: %s", err)
	}

	for _, v := range credibleOntIds {
		if JWTCredential.Payload.Iss == v {
			return nil
		}
	}
	return fmt.Errorf("VerifyJWTCredibleOntId failed")
}

func (this *Credential) VerifyJWTExpirationDate(credential string) error {
	JWTCredential, err := DeserializeJWT(credential)
	if err != nil {
		return fmt.Errorf("VerifyJWTExpirationDate, DeserializeJWT error: %s", err)
	}

	now := time.Now().UTC()
	if JWTCredential.Payload.Exp != 0 {
		if now.Unix() > JWTCredential.Payload.Exp {
			return fmt.Errorf("VerifyJWTExpirationDate expirationDate failed")
		}
	}
	return nil
}

func (this *Credential) VerifyJWTIssuanceDate(credential string) error {
	JWTCredential, err := DeserializeJWT(credential)
	if err != nil {
		return fmt.Errorf("VerifyJWTIssuanceDate, DeserializeJWT error: %s", err)
	}

	now := time.Now().UTC()
	if JWTCredential.Payload.Nbf != 0 {
		if now.Unix() < JWTCredential.Payload.Nbf {
			return fmt.Errorf("VerifyJWTIssuanceDate issuanceDate nbf failed")
		}
	}
	if JWTCredential.Payload.Iat != 0 {
		if now.Unix() < JWTCredential.Payload.Iat {
			return fmt.Errorf("VerifyJWTIssuanceDate issuanceDate iat failed")
		}
	}
	return nil
}

func (this *Credential) VerifyJWTIssuerSignature(credential string) error {
	JWTCredential, err := DeserializeJWT(credential)
	if err != nil {
		return fmt.Errorf("VerifyJWTIssuerSignature, DeserializeJWT error: %s", err)
	}

	msg, err := JWTCredential.SignData()
	if err != nil {
		return fmt.Errorf("VerifyJWTIssuerSignature, JWTCredential.SignData error: %s", err)
	}
	err = this.verifyJWSProof(JWTCredential.Payload.Iss, JWTCredential.Header.Kid, msg, JWTCredential.Jws)
	if err != nil {
		return fmt.Errorf("VerifyJWTIssuerSignature, this.VerifyJWSProof error: %s", err)
	}
	return nil
}

func (this *Credential) verifyJWSProof(ontId, kid string, msg []byte, jws string) error {
	sig, err := base64.StdEncoding.DecodeString(jws)
	if err != nil {
		return fmt.Errorf("VerifyJWSProof, base64.StdEncoding.DecodeString jws error: %s", err)
	}

	publicKeyHex, err := this.GetPublicKey(ontId, kid)
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
	JWTCredential, err := DeserializeJWT(credential)
	if err != nil {
		return fmt.Errorf("VerifyJWTStatus, DeserializeJWT error: %s", err)
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
	JWTCredential, err := DeserializeJWT(credential)
	if err != nil {
		return common.UINT256_EMPTY, fmt.Errorf("RevokeJWTCredentialByHolder, DeserializeJWT error: %s", err)
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
	JWTCredential, err := DeserializeJWT(credential)
	if err != nil {
		return common.UINT256_EMPTY, fmt.Errorf("RemoveJWTCredential, DeserializeJWT error: %s", err)
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
	header, err := makeJWTHeader(pkInfo.Type, pkInfo.Id)
	if err != nil {
		return "", fmt.Errorf("CreateJWTPresentation, makeJWTHeader error: %s", err)
	}

	now := time.Now().UTC().Unix()
	var domain interface{}
	proof, err := this.createProof(ontId, signer, "", domain, now)
	if err != nil {
		return "", fmt.Errorf("CreateJWTPresentation, this.CreateProof error: %s", err)
	}
	proof.VerificationMethod = ""
	proof.Type = ""
	// check credentials
	for _, v := range credentials {
		_, err := DeserializeJWT(v)
		if err != nil {
			return "", fmt.Errorf("CreateJWTPresentation, DeserializeJWT error: %s", err)
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

func (this *Credential) JWTCred2Json(jwtCred string) (*VerifiableCredential, error) {
	JWTCredential, err := DeserializeJWT(jwtCred)
	if err != nil {
		return nil, fmt.Errorf("JWTCred2Json, DeserializeJWT error: %s", err)
	}

	if JWTCredential.Payload.VC == nil {
		return nil, fmt.Errorf("JWTCred2Json, JWTCredential is not a credential error: %s", err)
	}

	credential := new(VerifiableCredential)
	credential.Id = JWTCredential.Payload.Jti
	credential.Context = JWTCredential.Payload.VC.Context
	credential.Type = JWTCredential.Payload.VC.Type

	issuer, err := genIdObject(JWTCredential.Payload.Iss, JWTCredential.Payload.VC.Issuer)
	if err != nil {
		return nil, fmt.Errorf("JWTCred2Json, genIdObject error: %s", err)
	}
	credential.Issuer = issuer

	t := JWTCredential.Payload.Iat
	if JWTCredential.Payload.Iat == 0 {
		t = JWTCredential.Payload.Nbf
	}
	issuanceDate := time.Unix(t, 0).UTC().Format("2006-01-02T15:04:05Z")
	credential.IssuanceDate = issuanceDate

	expirationDate := time.Unix(JWTCredential.Payload.Exp, 0).UTC().Format("2006-01-02T15:04:05Z")
	credential.ExpirationDate = expirationDate
	credential.CredentialSubject = JWTCredential.Payload.VC.CredentialSubject
	credential.CredentialStatus = JWTCredential.Payload.VC.CredentialStatus

	// create proof
	credential.Proof = JWTCredential.Payload.VC.Proof
	credential.Proof.VerificationMethod = JWTCredential.Header.Kid
	credential.Proof.Type = JsonSignType[JWTCredential.Header.Alg]
	credential.Proof.Challenge = JWTCredential.Payload.Nonce
	credential.Proof.Domain = JWTCredential.Payload.Aud
	credential.Proof.Jws = JWTCredential.Jws

	return credential, nil
}

func (this *Credential) JWTPresentation2Json(jwtPresentation string) (*VerifiablePresentation, error) {
	JWTPresentation, err := DeserializeJWT(jwtPresentation)
	if err != nil {
		return nil, fmt.Errorf("JWTPresentation2Json, JWTPresentation.Deserialization error: %s", err)
	}

	if JWTPresentation.Payload.VP == nil {
		return nil, fmt.Errorf("JWTPresentation2Json, JWTPresentation is not a presentation error: %s", err)
	}

	presentation := new(VerifiablePresentation)
	presentation.Id = JWTPresentation.Payload.Jti
	presentation.Context = JWTPresentation.Payload.VP.Context
	presentation.Type = JWTPresentation.Payload.VP.Type

	holder, err := genIdObject(JWTPresentation.Payload.Iss, JWTPresentation.Payload.VP.Holder)
	if err != nil {
		return nil, fmt.Errorf("JWTCred2Json, genIdObject error: %s", err)
	}
	presentation.Holder = holder

	for _, v := range JWTPresentation.Payload.VP.VerifiableCredential {
		cred, err := this.JWTCred2Json(v)
		if err != nil {
			return nil, fmt.Errorf("JWTPresentation2Json, this.JWTCred2Json error: %s", err)
		}
		presentation.VerifiableCredential = append(presentation.VerifiableCredential, cred)
	}

	// create proof
	proof := new(Proof)
	proof = JWTPresentation.Payload.VP.Proof
	proof.VerificationMethod = JWTPresentation.Header.Kid
	proof.Type = JsonSignType[JWTPresentation.Header.Alg]
	proof.Challenge = JWTPresentation.Payload.Nonce
	proof.Domain = JWTPresentation.Payload.Aud
	proof.Jws = JWTPresentation.Jws

	presentation.Proof = append(presentation.Proof, proof)
	return presentation, nil
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

func DeserializeJWT(jwt string) (*JWTCredential, error) {
	slice := strings.Split(jwt, ".")
	if len(slice) != 3 {
		return nil, fmt.Errorf("JWTCredential Deserialization, length of elem is not 3")
	}
	headerb, err := base64.StdEncoding.DecodeString(slice[0])
	if err != nil {
		return nil, fmt.Errorf("JWTCredential Deserialization, base64.StdEncoding.DecodeString header error: %s", err)
	}
	header := new(Header)
	err = json.Unmarshal(headerb, header)
	if err != nil {
		return nil, fmt.Errorf("JWTCredential Deserialization, json.Unmarshal header error: %s", err)
	}

	payload := new(Payload)
	payloadb, err := base64.StdEncoding.DecodeString(slice[1])
	if err != nil {
		return nil, fmt.Errorf("JWTCredential Deserialization, base64.StdEncoding.DecodeString payload error: %s", err)
	}
	err = json.Unmarshal(payloadb, payload)
	if err != nil {
		return nil, fmt.Errorf("JWTCredential Deserialization, json.Unmarshal payload error: %s", err)
	}

	jws := slice[2]
	r := &JWTCredential{
		Header:  header,
		Payload: payload,
		Jws:     jws,
	}
	return r, nil
}

func makeJWTHeader(proofType, verificationMethod string) (*Header, error) {
	if proofType == "" || verificationMethod == "" {
		return nil, fmt.Errorf("makeJWTHeader, proof is illegal")
	}
	header := &Header{
		Alg: JWTSignType[proofType],
		Typ: HEADER_TYPE,
		Kid: verificationMethod,
	}
	return header, nil
}
