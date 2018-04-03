package common

import "math/big"

const CRYPTO_SCHEME_DEFAULT = "SHA256withECDSA"

type Balance struct {
	Ont *big.Int
	Ong *big.Int
}

type SmartContactEvent struct {
	Address interface{} `json:"CodeHash"`
	States  []interface{}
	TxHash  interface{}
}
