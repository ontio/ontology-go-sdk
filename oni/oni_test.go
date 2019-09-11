package oni

import (
	"encoding/json"
	"github.com/ontio/ontology-crypto/keypair"
	"github.com/ontio/ontology-crypto/signature"
	oniType "github.com/ontio/ontology-go-sdk/oni/types"
	"github.com/ontio/ontology/common"
	"github.com/ontio/ontology/core/types"
	"github.com/stretchr/testify/assert"
	"testing"
)

const (
	asset_symbol    = "save"
	acc_pwd         = "passwordtest"
	file_crypto_pwd = "123456"
	tx_hash         = "98c3dd24adba0b3355254420d081e9919b383e2b313e13ff14190be973c39042"
	address         = "AbEr4Gwt6AUoijr3Qrn98hSFEuSFPZ914Q"
	to_addr         = "APnoekqXUkNDFQMbnnBCsMPQgmWoQQmsd4"
	label           = "test"
	priv_wif        = "KzPXqyPvsmPRfxEfkvBCUeJPuGykVUGC9dSZaSqW7rrXUvvFQthL"
	wallet_str      = `{
  "name": "MyWallet",
  "version": "1.1",
  "scrypt": {
    "p": 8,
    "n": 16384,
    "r": 8,
    "dkLen": 64
  },
  "accounts": [
    {
      "address": "AbEr4Gwt6AUoijr3Qrn98hSFEuSFPZ914Q",
      "enc-alg": "aes-256-gcm",
      "key": "jjLNfpRkerTvy4ugdrcQRNNZ8h7ZbCsNKKCnrmXuM1LUgldmZ8FMpEq+IMqWJfKM",
      "algorithm": "ECDSA",
      "salt": "r7paAMqeipzDVv2VzdOffA==",
      "parameters": {
        "curve": "P-256"
      },
      "label": "qiluge",
      "publicKey": "028393abb40933209b57c42b7476e5b46caff8616ff2a4ab43e26182e8ed094237",
      "signatureScheme": "SHA256withECDSA",
      "isDefault": true,
      "lock": false
    }
  ]
}`
)

var oni = NewOniWithAddr("http://127.0.0.1:10335")

// the sync instance should logout account
func TestONI_NewAccount(t *testing.T) {
	privKey, _, err := oni.NewAccount(acc_pwd, "test", signature.SHA256withECDSA, true)
	if err != nil {
		t.Fatal(err)
	}
	wif, err := keypair.Key2WIF(privKey)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("priv key is %s", wif)
	pubkey := privKey.Public()
	pubkeyData := keypair.SerializePublicKey(pubkey)
	t.Logf("pub key is %x", pubkeyData)
	addr := types.AddressFromPubKey(pubkey)
	t.Logf("addr is %s", addr.ToBase58())
}

func TestONI_CurrentAccount(t *testing.T) {
	privKey, pub, addr, scheme, err := oni.CurrentAccount()
	if err != nil {
		t.Fatal(err)
	}
	if privKey != nil {
		wif, err := keypair.Key2WIF(privKey)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("priv key is %s", wif)
		pubkey := privKey.Public()
		pubkeyData := keypair.SerializePublicKey(pubkey)
		t.Logf("pub key is %x", pubkeyData)
		assert.Equal(t, pub, pubkey)
		address := types.AddressFromPubKey(pubkey)
		t.Logf("addr is %s", addr.ToBase58())
		assert.Equal(t, addr, address)
		t.Logf("scheme is %d", scheme)
	} else {
		pubkeyData := keypair.SerializePublicKey(pub)
		t.Logf("pub key is %x", pubkeyData)
		t.Logf("addr is %s", addr.ToBase58())
	}
}

func TestONI_Logout(t *testing.T) {
	err := oni.Logout()
	if err != nil {
		t.Fatal(err)
	}
}

func TestONI_ExportPrivKey(t *testing.T) {
	privKey, err := oni.ExportPrivKey(acc_pwd)
	if err != nil {
		t.Fatal(err)
	}
	wif, err := keypair.Key2WIF(privKey)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("priv key is %s", wif)
}

func TestONI_ExportWalletFile(t *testing.T) {
	wallet, err := oni.ExportWalletFile()
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("wallet is: %s", wallet)
}

// ensure sync node account logout
func TestONI_ImportWithWalletFile(t *testing.T) {
	err := oni.ImportWithWalletFile(wallet_str, acc_pwd)
	if err != nil {
		t.Fatal(err)
	}
}

// ensure sync node account logout
func TestONI_ImportWithPrivateKey(t *testing.T) {
	privKey, _ := keypair.WIF2Key([]byte(priv_wif))
	err := oni.ImportWithPrivateKey(privKey, acc_pwd, label)
	if err != nil {
		t.Fatal(err)
	}
}

func TestONI_Balance(t *testing.T) {
	addr, _ := common.AddressFromBase58(address)
	balance, err := oni.Balance(addr)
	if err != nil {
		t.Fatal(err)
	}
	jsonRes, _ := json.MarshalIndent(balance, "", "	")
	t.Log(string(jsonRes))
}

func TestONI_SendAsset(t *testing.T) {
	to, _ := common.AddressFromBase58(to_addr)
	amount := "1.000003"
	txHash, err := oni.SendAsset(to, amount, asset_symbol, acc_pwd)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(txHash)
}

func TestONI_GetTxRecords(t *testing.T) {
	limit := uint64(3)
	records, err := oni.GetTxRecords(address, oniType.TxType(0), asset_symbol, limit, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	assert.True(t, uint64(len(records)) <= limit)
	jsonRes, _ := json.MarshalIndent(records, "", "	")
	t.Log(string(jsonRes))
}

func TestONI_GetSCEventByTxHash(t *testing.T) {
	hash, _ := common.Uint256FromHexString(tx_hash)
	event, err := oni.GetSCEventByTxHash(hash)
	if err != nil {
		t.Fatal(err)
	}
	jsonRes, _ := json.MarshalIndent(event, "", "	")
	t.Log(string(jsonRes))
}

func TestONI_GetSCEventByHeight(t *testing.T) {
	// fixme: wait oni interface update
	events, err := oni.GetSCEventByHeight(106534)
	if err != nil {
		t.Fatal(err)
	}
	jsonRes, _ := json.MarshalIndent(events, "", "	")
	t.Log(string(jsonRes))
}

func TestONI_PreExecSmartContract(t *testing.T) {
	contractAddr := "AFmseVrdL9f9oyCzZefL9tG6UbviKTaSnK"
	contract, _ := common.AddressFromBase58(contractAddr)
	method := "FsGetFileInfo"
	params := []interface{}{"zb2rhk1JBGAf9ivtroSNe2xsWLuV15BLjMZMknpVPq58Qepgr"}
	result, err := oni.PreExecSmartContract(contract, method, params)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("%x", result)
}

func TestONI_InvokeSmartContract(t *testing.T) {
	contractAddr := "AFmseVrdL9f9oyCzZefL9tG6UbviKTaSnK"
	contract, _ := common.AddressFromBase58(contractAddr)
	method := "FsGetFileInfo"
	params := []interface{}{"zb2rhk1JBGAf9ivtroSNe2xsWLuV15BLjMZMknpVPq58Qepgr"}
	result, err := oni.InvokeSmartContract(contract, method, acc_pwd, params)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("%x", result)
}
