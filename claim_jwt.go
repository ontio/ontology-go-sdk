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
}

type Payload struct {
	Sub string `json:"sub,omitempty"`
	Jti string `json:"jti,omitempty"`
	Iss string `json:"iss,omitempty"`
	Nbf int64  `json:"nbf,omitempty"`
	Iat int64  `json:"iat,omitempty"`
	Exp int64  `json:"exp,omitempty"`
	VC  *VC    `json:"vc,omitempty"`
}

type JWTClaim struct {
	Header  *Header  `json:"header"`
	Payload *Payload `json:"payload"`
	Jws     string   `json:"jws"`
}

func (this *Claim) CreateJWTClaim(contexts []string, types []string, credentialSubject interface{}, issuerId interface{},
	expirationDateTimestamp int64, signer *Account) (string, error) {
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
	vc := &VC{
		Context:           append(DefaultContext, contexts...),
		Type:              append(DefaultClaimType, types...),
		Issuer:            is,
		CredentialSubject: cs,
		CredentialStatus: &CredentialStatus{
			Id:   this.claimContractAddress.ToHexString(),
			Type: CLAIM_STATUS_TYPE,
		},
	}
	payload := &Payload{
		Sub: sub,
		Jti: UUID_PREFIX + uuid.NewV4().String(),
		Iss: ontId,
		Nbf: now,
		Iat: now,
		Exp: expirationDateTimestamp,
		VC:  vc,
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

	return this.RevokeClaim(contractAddress, gasPrice, gasLimit, JWTClaim.Payload.Jti, holder, index, signer, payer)
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
