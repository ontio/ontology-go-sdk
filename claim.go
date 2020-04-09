package ontology_go_sdk

import (
	"encoding/base64"
	"encoding/json"
	"github.com/ontio/ontology/common"
	"time"
)

type Claim struct {
	context  string
	id       string
	claim    map[string]interface{}
	claimStr string
}

func NewClaim(controller *Controller, ctx string, clmMap map[string]interface{},
	metadata map[string]string, clmRevMap map[string]interface{}, publicKeyId string, expireTime int64) (*Claim, error) {
	iss := metadata["Issuer"]
	sub := metadata["Subject"]
	header := NewHeader(publicKeyId)
	payload, err := NewPayload("v1.0", iss, sub, time.Now().Unix(), expireTime, ctx, clmMap, clmRevMap)
	if err != nil {
		return nil, err
	}
	headerBs, err := header.getJson()
	if err != nil {
		return nil, err
	}
	payloadBs, err := payload.getJson()
	if err != nil {
		return nil, err
	}
	headerStr := base64.StdEncoding.EncodeToString(headerBs)
	payloadStr := base64.StdEncoding.EncodeToString(payloadBs)
	sig, err := controller.Sign([]byte(headerStr + "." + payloadStr))
	if err != nil {
		return nil, err
	}
	claimStr := headerStr + "." + payloadStr + "." + base64.StdEncoding.EncodeToString(sig)
	return &Claim{
		context:  ctx,
		claimStr: claimStr,
	}, nil
}

func (this *Claim) GetClaimStr() string {
	return this.claimStr
}

type Header struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
	Kid string `json:"kid"`
}

func NewHeader(kid string) *Header {
	return &Header{
		Alg: "ONT-ES256",
		Typ: "JWT-X",
		Kid: kid,
	}
}
func (this *Header) getJson() ([]byte, error) {
	bs, err := json.Marshal(this)
	if err != nil {
		return nil, err
	}
	return bs, nil
}

type Payload struct {
	Ver       string                 `json:"ver"`
	Iss       string                 `json:"iss"`
	Sub       string                 `json:"sub"`
	Iat       int64                  `json:"iat"`
	Exp       int64                  `json:"exp"`
	Jti       string                 `json:"jti"`
	Context   string                 `json:"@context"`
	ClmMap    map[string]interface{} `json:"clm"`
	ClmRevMap map[string]interface{} `json:"clm-rev"`
}

func NewPayload(ver, iss, sub string, iat, exp int64, ctx string, clmMap, clmRevMap map[string]interface{}) (*Payload, error) {
	payload := &Payload{
		Ver:       ver,
		Iss:       iss,
		Sub:       sub,
		Iat:       iat,
		Exp:       exp,
		Context:   ctx,
		ClmMap:    clmMap,
		ClmRevMap: clmRevMap,
	}
	pbs, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	payload.Jti = common.ToHexString(pbs)
	return payload, nil
}

func (this *Payload) getJson() ([]byte, error) {
	bs, err := json.Marshal(this)
	if err != nil {
		return nil, err
	}
	return bs, nil
}

type MetaData struct {
	createTime string
	meta       map[string]string
}

func (this *MetaData) GetJson() interface{} {
	this.meta["CreateTime"] = this.createTime

	return this.meta
}

type SignatureInfo struct {
	format      string
	algorithm   string
	value       []byte
	publicKeyId string
}

func NewSignatureInfo(publicKeyId string, val []byte) *SignatureInfo {
	return &SignatureInfo{
		format:      "pgp",
		algorithm:   "ECDSAwithSHA256",
		value:       val,
		publicKeyId: publicKeyId,
	}
}

func (this *SignatureInfo) getJson() map[string]interface{} {
	signature := make(map[string]interface{})
	signature["Format"] = this.format
	signature["Algorithm"] = this.algorithm
	signature["Value"] = this.value
	signature["PublicKeyId"] = this.publicKeyId
	return signature
}
