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

// fixme: wait oni interface update
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

// fixme: wait oni interface update
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

func TestONI_EncryptFile(t *testing.T) {
	path := "G:\\test"
	err := oni.EncryptFile(path, file_crypto_pwd)
	assert.Nil(t, err)
}

// fixme: wait oni to fix interface
func TestONI_DecryptFile(t *testing.T) {
	path := "G:\\test"
	err := oni.DecryptFile(path, file_crypto_pwd)
	assert.Nil(t, err)
}

func TestONI_DeleteFile(t *testing.T) {
	// the file should be existed
	fileHash := "zb2rhdvvhgWUN4eeEhf7U7YhTAV2kzpdE8zM7Vob2HzmLnCv8"
	resp, err := oni.DeleteFile(fileHash)
	if err != nil {
		t.Fatal(err)
	}
	jsonRes, _ := json.MarshalIndent(resp, "", "	")
	t.Log(string(jsonRes))
}

func TestONI_DeleteFiles(t *testing.T) {
	fileHashes := []string{"zb2rhdvvhgWUN4eeEhf7U7YhTAV2kzpdE8zM7Vob2HzmLnCv8",
		"zb2rhewfkMZao5rRpLBbMsQc5RCeptk1C2yqtg77fE4aQkTJD"}
	resp, err := oni.DeleteFiles(fileHashes)
	if err != nil {
		t.Fatal(err)
	}
	jsonRes, _ := json.MarshalIndent(resp, "", "	")
	t.Log(string(jsonRes))
}

func TestONI_SetUserSpace(t *testing.T) {
	account, _ := common.AddressFromBase58(address)
	sizeOperation := &oniType.Operation{ // increase 100 MB
		Type:  oniType.OPERATION_INCREASE,
		Value: 102400,
	}
	timeOperation := &oniType.Operation{ // increase 1 day
		Type:  oniType.OPERATION_INCREASE,
		Value: 60 * 60 * 24, // 60s * 60 * 24
	}
	txHash, err := oni.SetUserSpace(account, sizeOperation, timeOperation, acc_pwd)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(txHash)
}

func TestONI_CostSetUserSpace(t *testing.T) {
	account, _ := common.AddressFromBase58(address)
	sizeOperation := &oniType.Operation{ // increase 100 MB
		Type:  oniType.OPERATION_INCREASE,
		Value: 102400,
	}
	timeOperation := &oniType.Operation{ // increase 1 day
		Type:  oniType.OPERATION_INCREASE,
		Value: 60 * 60 * 24, // 60s * 60 * 24
	}
	resp, err := oni.CostSetUserSpace(account, sizeOperation, timeOperation)
	if err != nil {
		t.Fatal(err)
	}
	jsonRes, _ := json.MarshalIndent(resp, "", "	")
	t.Log(string(jsonRes))
}

func TestONI_GetUserSpace(t *testing.T) {
	account, _ := common.AddressFromBase58(address)
	resp, err := oni.GetUserSpace(account)
	if err != nil {
		t.Fatal(err)
	}
	jsonRes, _ := json.MarshalIndent(resp, "", "	")
	t.Log(string(jsonRes))
}

func TestONI_GetUserSpaceRecords(t *testing.T) {
	account, _ := common.AddressFromBase58(address)
	resp, err := oni.GetUserSpaceRecords(account, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	jsonRes, _ := json.MarshalIndent(resp, "", "	")
	t.Log(string(jsonRes))
}

func TestONI_GetTransferList(t *testing.T) {
	resp, err := oni.GetTransferList(oniType.TRANSFER_TYPE_DOWNLOADING, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	jsonRes, _ := json.MarshalIndent(resp, "", "	")
	t.Log(string(jsonRes))
}

func TestONI_GetTransferDetail(t *testing.T) {
	transferId := "b295c3f3-d501-11e9-96a5-80ce6248ca42"
	resp, err := oni.GetTransferDetail(oniType.TRANSFER_TYPE_DOWNLOADING, transferId)
	if err != nil {
		t.Fatal(err)
	}
	jsonRes, _ := json.MarshalIndent(resp, "", "	")
	t.Log(string(jsonRes))
}

func TestONI_DeleteCompleteTask(t *testing.T) {
	taskIds := []string{"1329d29c-b66c-11e9-ac70-88e9fe5b16bf"}
	resp, err := oni.DeleteCompleteTask(taskIds)
	if err != nil {
		t.Fatal(err)
	}
	jsonRes, _ := json.MarshalIndent(resp, "", "	")
	t.Log(string(jsonRes))
}

func TestONI_DownloadFile(t *testing.T) {
	hash := "QmScUeAHzheFiQLP2aeCW95Wej84F6QGmHfWtHatS98yx8"
	url := "oni://share/b57c76c0"
	err := oni.DownloadFile(hash, url, "", acc_pwd, 10, true)
	assert.Nil(t, err)
}

func TestONI_DownloadPause(t *testing.T) {
	taskIds := []string{"ab553f7d-d509-11e9-96a6-80ce6248ca42"}
	resp, err := oni.DownloadPause(taskIds)
	if err != nil {
		t.Fatal(err)
	}
	jsonRes, _ := json.MarshalIndent(resp, "", "	")
	t.Log(string(jsonRes))
}

func TestONI_DownloadResume(t *testing.T) {
	taskIds := []string{"ab553f7d-d509-11e9-96a6-80ce6248ca42"}
	resp, err := oni.DownloadResume(taskIds)
	if err != nil {
		t.Fatal(err)
	}
	jsonRes, _ := json.MarshalIndent(resp, "", "	")
	t.Log(string(jsonRes))
}

func TestONI_DownloadFailedRetry(t *testing.T) {
	taskIds := []string{"ab553f7d-d509-11e9-96a6-80ce6248ca42"}
	resp, err := oni.DownloadFailedRetry(taskIds)
	if err != nil {
		t.Fatal(err)
	}
	jsonRes, _ := json.MarshalIndent(resp, "", "	")
	t.Log(string(jsonRes))
}

func TestONI_DownloadCancel(t *testing.T) {
	taskIds := []string{"ab553f7d-d509-11e9-96a6-80ce6248ca42"}
	resp, err := oni.DownloadCancel(taskIds)
	if err != nil {
		t.Fatal(err)
	}
	jsonRes, _ := json.MarshalIndent(resp, "", "	")
	t.Log(string(jsonRes))
}

func TestONI_GetDownloadFileInfo(t *testing.T) {
	url := "oni://share/b57c76c0"
	resp, err := oni.GetDownloadFileInfo(url)
	if err != nil {
		t.Fatal(err)
	}
	jsonRes, _ := json.MarshalIndent(resp, "", "	")
	t.Log(string(jsonRes))
}

func TestONI_GetDownloadFileList(t *testing.T) {
	resp, err := oni.GetDownloadFileList(oniType.FILE_TYPE_ALL, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	jsonRes, _ := json.MarshalIndent(resp, "", "	")
	t.Log(string(jsonRes))
}

func TestONI_UploadFile(t *testing.T) {
	jsonReq := `{
    "Path": "F:\\Program Files\\Seeker\\icudtl.dat",
    "Desc": "wallet.dat",
    "Duration": 0,
    "Interval": 3600,
    "Privilege": 1,
    "CopyNum": 0,
    "EncryptPassword": "",
    "WhiteList": [],
    "Share": false,
    "StoreType": 0
}`
	req := &oniType.CommitUploadTaskReq{}
	err := json.Unmarshal([]byte(jsonReq), req)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := oni.UploadFile(req)
	if err != nil {
		t.Fatal(err)
	}
	jsonRes, _ := json.MarshalIndent(resp, "", "	")
	t.Log(string(jsonRes))
}

func TestONI_UploadPause(t *testing.T) {
	taskIds := []string{
		"df0c239b-d507-11e9-96a6-80ce6248ca42",
		"db611503-d50a-11e9-96a6-80ce6248ca42",
	}
	resp, err := oni.UploadPause(taskIds)
	if err != nil {
		t.Fatal(err)
	}
	jsonRes, _ := json.MarshalIndent(resp, "", "	")
	t.Log(string(jsonRes))
}

func TestONI_UploadResume(t *testing.T) {
	taskIds := []string{
		"df0c239b-d507-11e9-96a6-80ce6248ca42",
		"db611503-d50a-11e9-96a6-80ce6248ca42",
	}
	resp, err := oni.UploadResume(taskIds)
	if err != nil {
		t.Fatal(err)
	}
	jsonRes, _ := json.MarshalIndent(resp, "", "	")
	t.Log(string(jsonRes))
}

func TestONI_UploadFailedRetry(t *testing.T) {
	taskIds := []string{
		"df0c239b-d507-11e9-96a6-80ce6248ca42",
		"db611503-d50a-11e9-96a6-80ce6248ca42",
	}
	resp, err := oni.UploadFailedRetry(taskIds)
	if err != nil {
		t.Fatal(err)
	}
	jsonRes, _ := json.MarshalIndent(resp, "", "	")
	t.Log(string(jsonRes))
}

func TestONI_UploadCancel(t *testing.T) {
	taskIds := []string{
		"df0c239b-d507-11e9-96a6-80ce6248ca42",
		"db611503-d50a-11e9-96a6-80ce6248ca42",
	}
	resp, err := oni.UploadCancel(taskIds)
	if err != nil {
		t.Fatal(err)
	}
	jsonRes, _ := json.MarshalIndent(resp, "", "	")
	t.Log(string(jsonRes))
}

func TestONI_UpdateFileWhiteList(t *testing.T) {
	fileHash := "QmS7ouwGqoxsfyiK2DFucmuhMvRdhji65yEFiYi5UthPej"
	whitelist := []*oniType.WhiteListAddress{
		{Addr: to_addr, StartHeight: 1, ExpiredHeight: 3999999},
	}
	txHash, err := oni.UpdateFileWhiteList(fileHash, oniType.WHITE_LIST_OPERATE_REPLACE, whitelist)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(txHash)
}

func TestONI_GetUploadFileInfo(t *testing.T) {
	fileHash := "QmS7ouwGqoxsfyiK2DFucmuhMvRdhji65yEFiYi5UthPej"
	resp, err := oni.GetUploadFileInfo(fileHash)
	if err != nil {
		t.Fatal(err)
	}
	jsonRes, _ := json.MarshalIndent(resp, "", "	")
	t.Log(string(jsonRes))
}

func TestONI_GetFSSetting(t *testing.T) {
	resp, err := oni.GetFSSetting()
	if err != nil {
		t.Fatal(err)
	}
	jsonRes, _ := json.MarshalIndent(resp, "", "	")
	t.Log(string(jsonRes))
}

func TestONI_GetFileWhiteList(t *testing.T) {
	fileHash := "QmS7ouwGqoxsfyiK2DFucmuhMvRdhji65yEFiYi5UthPej"
	resp, err := oni.GetFileWhiteList(fileHash)
	if err != nil {
		t.Fatal(err)
	}
	jsonRes, _ := json.MarshalIndent(resp, "", "	")
	t.Log(string(jsonRes))
}

func TestONI_GetUploadFileList(t *testing.T) {
	resp, err := oni.GetUploadFileList(oniType.FILE_TYPE_ALL, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	jsonRes, _ := json.MarshalIndent(resp, "", "	")
	t.Log(string(jsonRes))
}

func TestONI_EstimateUploadFileFee(t *testing.T) {
	filePath := "F:\\Program Files\\Seeker\\icudtl.dat"
	duration := uint32(60 * 60 * 24)
	proveInterval := uint32(60 * 60)
	copyNum := uint32(3)
	whiteListCount := uint32(2)
	storeType := oniType.STORE_TYPE_NORMAL
	resp, err := oni.EstimateUploadFileFee(filePath, duration, proveInterval, copyNum, whiteListCount, storeType)
	if err != nil {
		t.Fatal(err)
	}
	jsonRes, _ := json.MarshalIndent(resp, "", "	")
	t.Log(string(jsonRes))
}

func TestONI_GetCurrentChannel(t *testing.T) {
	resp, err := oni.GetCurrentChannel()
	if err != nil {
		t.Fatal(err)
	}
	jsonRes, _ := json.MarshalIndent(resp, "", "	")
	t.Log(string(jsonRes))
}

func TestONI_SwitchChannel(t *testing.T) {
	partner, _ := common.AddressFromBase58(to_addr)
	err := oni.SwitchChannel(partner, acc_pwd)
	if err != nil {
		t.Fatal(err)
	}
}

func TestONI_ChannelIsSyncing(t *testing.T) {
	res, err := oni.ChannelIsSyncing()
	if err != nil {
		t.Fatal(err)
	}
	t.Log(res)
}

func TestONI_ChannelInitProgress(t *testing.T) {
	resp, err := oni.ChannelInitProgress()
	if err != nil {
		t.Fatal(err)
	}
	jsonRes, _ := json.MarshalIndent(resp, "", "	")
	t.Log(string(jsonRes))
}

func TestONI_OpenChannel(t *testing.T) {
	partner, _ := common.AddressFromBase58("AcJdio7iRMzPxCWgBjSLSqKZcXMjNRtLpd")
	amount := "200"
	err := oni.OpenChannel(partner, acc_pwd, amount)
	if err != nil {
		t.Fatal(err)
	}
}

func TestONI_CloseChannel(t *testing.T) {
	partner, _ := common.AddressFromBase58("AcJdio7iRMzPxCWgBjSLSqKZcXMjNRtLpd")
	err := oni.CloseChannel(partner, acc_pwd)
	if err != nil {
		t.Fatal(err)
	}
}

func TestONI_WithdrawChannel(t *testing.T) {
	partner, _ := common.AddressFromBase58(to_addr)
	amount := "100"
	err := oni.WithdrawChannel(partner, acc_pwd, amount)
	if err != nil {
		t.Fatal(err)
	}
}

func TestONI_DepositChannel(t *testing.T) {
	partner, _ := common.AddressFromBase58(to_addr)
	amount := "100"
	err := oni.DepositChannel(partner, acc_pwd, amount)
	if err != nil {
		t.Fatal(err)
	}
}

func TestONI_GetAllChannels(t *testing.T) {
	resp, err := oni.GetAllChannels()
	if err != nil {
		t.Fatal(err)
	}
	jsonRes, _ := json.MarshalIndent(resp, "", "	")
	t.Log(string(jsonRes))
}

func TestONI_Revenue(t *testing.T) {
	resp, err := oni.Revenue()
	if err != nil {
		t.Fatal(err)
	}
	jsonRes, _ := json.MarshalIndent(resp, "", "	")
	t.Log(string(jsonRes))
}

func TestONI_MinerGetShardIncome(t *testing.T) {
	resp, err := oni.MinerGetShardIncome(1555091319, 1556091319, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	jsonRes, _ := json.MarshalIndent(resp, "", "	")
	t.Log(string(jsonRes))
}

func TestONI_ReconnectPeer(t *testing.T) {
	peers := []string{"tcp://40.73.102.177:10338"}
	resp, err := oni.ReconnectPeer(peers)
	if err != nil {
		t.Fatal(err)
	}
	jsonRes, _ := json.MarshalIndent(resp, "", "	")
	t.Log(string(jsonRes))
}

func TestONI_GetAllDns(t *testing.T) {
	resp, err := oni.GetAllDns()
	if err != nil {
		t.Fatal(err)
	}
	jsonRes, _ := json.MarshalIndent(resp, "", "	")
	t.Log(string(jsonRes))
}

func TestONI_GetRegisteredStoreNodeNum(t *testing.T) {
	resp, err := oni.GetRegisteredStoreNodeNum()
	if err != nil {
		t.Fatal(err)
	}
	t.Log(resp)
}

func TestONI_UpdateConfig(t *testing.T) {
	req := &oniType.UpdateConfigReq{DownloadPath: "~/Desktop"}
	err := oni.UpdateConfig(req)
	assert.Nil(t, err)
}

func TestONI_NetworkState(t *testing.T) {
	resp, err := oni.NetworkState()
	if err != nil {
		t.Fatal(err)
	}
	jsonRes, _ := json.MarshalIndent(resp, "", "	")
	t.Log(string(jsonRes))
}

func TestONI_CurrentHeight(t *testing.T) {
	height, err := oni.CurrentHeight()
	if err != nil {
		t.Fatal(err)
	}
	t.Log(height)
}

func TestONI_Version(t *testing.T) {
	version, err := oni.Version()
	if err != nil {
		t.Fatal(err)
	}
	t.Log(version)
}

func TestONI_SwitchChainId(t *testing.T) {
	err := oni.SwitchChainId("1", "config-1.json")
	assert.Nil(t, err)
}

func TestONI_ChainId(t *testing.T) {
	chainId, err := oni.ChainId()
	if err != nil {
		t.Fatal(err)
	}
	t.Log(chainId)
}

func TestONI_ChainIdList(t *testing.T) {
	resp, err := oni.ChainIdList()
	if err != nil {
		t.Fatal(err)
	}
	jsonRes, _ := json.MarshalIndent(resp, "", "	")
	t.Log(string(jsonRes))
}
