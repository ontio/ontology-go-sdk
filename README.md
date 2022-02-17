# Go SDK For Ontology

* [Go SDK For Ontology](#go-sdk-for-ontology)
	* [1. Overview](#1-overview)
	* [2. How to use?](#2-how-to-use)
		* [2.1 Block Chain API](#21-block-chain-api)
			* [2.1.1 Get current block height](#211-get-current-block-height)
			* [2.1.2 Get current block hash](#212-get-current-block-hash)
			* [2.1.3 Get block by height](#213-get-block-by-height)
			* [2.1.4 Get block by hash](#214-get-block-by-hash)
			* [2.1.5 Get transaction by transaction hash](#215-get-transaction-by-transaction-hash)
			* [2.1.6 Get block hash by block height](#216-get-block-hash-by-block-height)
			* [2.1.7 Get block height by transaction hash](#217-get-block-height-by-transaction-hash)
			* [2.1.8 Get transaction hashes of block by block height](#218-get-transaction-hashes-of-block-by-block-height)
			* [2.1.9 Get storage value of smart contract key](#219-get-storage-value-of-smart-contract-key)
			* [2.1.10 Get smart contract by contract address](#2110-get-smart-contract-by-contract-address)
			* [2.1.11 Get smart contract event by transaction hash](#2111-get-smart-contract-event-by-transaction-hash)
			* [2.1.12 Get all of smart contract events of block by block height](#2112-get-all-of-smart-contract-events-of-block-by-block-height)
			* [2.1.13 Get block merkle proof by transaction hash](#2113-get-block-merkle-proof-by-transaction-hash)
			* [2.1.14 Get transaction state of transaction pool](#2114-get-transaction-state-of-transaction-pool)
			* [2.1.15 Get transaction count in transaction pool](#2115-get-transaction-count-in-transaction-pool)
			* [2.1.16 Get version of Ontology](#2116-get-version-of-ontology)
			* [2.1.17 Get network id of Ontology](#2117-get-network-id-of-ontology)
			* [2.1.18 Send transaction to Ontology](#2118-send-transaction-to-ontology)
			* [2.19 Prepare execute transaction](#219-prepare-execute-transaction)
		* [2.2 Wallet API](#22-wallet-api)
			* [2.2.1 Create or Open Wallet](#221-create-or-open-wallet)
			* [2.2.2 Save Wallet](#222-save-wallet)
			* [2.2.3 New account](#223-new-account)
			* [2.2.4 New default setting account](#224-new-default-setting-account)
			* [2.2.5 New account from wif private key](#225-new-account-from-wif-private-key)
			* [2.2.5 Delete account](#225-delete-account)
			* [2.2.5 Get default account](#225-get-default-account)
			* [2.2.6 Set default account](#226-set-default-account)
			* [2.2.7 Get account by address](#227-get-account-by-address)
			* [2.2.8 Get account by label](#228-get-account-by-label)
			* [2.2.9 Get account by index](#229-get-account-by-index)
			* [2.2.10 Get account count of wallet](#2210-get-account-count-of-wallet)
			* [2.2.11 Get default account data](#2211-get-default-account-data)
			* [2.2.12 Get account data by address](#2212-get-account-data-by-address)
			* [2.2.13 Get account data by label](#2213-get-account-data-by-label)
			* [2.2.14 Get account data by index](#2214-get-account-data-by-index)
			* [2.2.15 Set account label](#2215-set-account-label)
			* [2.2.16 Set signature scheme of account](#2216-set-signature-scheme-of-account)
			* [2.2.17 Change account password](#2217-change-account-password)
			* [2.2.18 Import account to wallet](#2218-import-account-to-wallet)
			* [2.2.19 Export account to a new wallet](#2219-export-account-to-a-new-wallet)
		* [2.3 ONT Contract API](#23-ont-contract-api)
			* [2.3.1 Get balance](#231-get-balance)
			* [2.3.2 Transfer](#232-transfer)
			* [2.3.3 Multiple Transfer](#233-multiple-transfer)
			* [2.3.4 Approve](#234-approve)
			* [2.3.5 Approve Balance](#235-approve-balance)
			* [2.3.6 TransferFrom](#236-transferfrom)
			* [2.3.7 Get balance V2](#237-get-balance-v2)
			* [2.3.8 Transfer V2](#238-transfer-v2)
			* [2.3.9 Multiple Transfer V2](#239-multiple-transfer-v2)
			* [2.3.10 Approve V2](#2310-approve-v2)
			* [2.3.11 Allowance V2](#2311-allowance-v2)
			* [2.3.12 Transfer From V2](#2312-transfer-from-v2)
		* [2.4 ONG Contract API](#24-ong-contract-api)
			* [2.4.1 Get balance](#241-get-balance)
			* [2.4.2 Transfer](#242-transfer)
			* [2.4.3 Multiple Transfer](#243-multiple-transfer)
			* [2.4.4 Approve](#244-approve)
			* [2.4.5 Approve Balance](#245-approve-balance)
			* [2.4.6 TransferFrom](#246-transferfrom)
			* [2.4.7 Withdraw ONG](#247-withdraw-ong)
			* [2.4.8 Get unbound ONG](#248-get-unbound-ong)
			* [2.4.9 Get balance V2](#249-get-balance-v2)
			* [2.4.10 Transfer V2](#2410-transfer-v2)
			* [2.4.11 Multiple Transfer V2](#2411-multiple-transfer-v2)
			* [2.4.12 Approve V2](#2412-approve-v2)
			* [2.4.13 Approve Balance V2](#2413-approve-balance-v2)
			* [2.4.14 TransferFrom V2](#2414-transferfrom-v2)
			* [2.4.15 Withdraw ONG V2](#2415-withdraw-ong-v2)
			* [2.4.16 Get unbound ONG V2](#2416-get-unbound-ong-v2)
        * [2.5 ONT ID API](#25-ont-id-api)
			* [2.5.1 RegID With PublicKey](#251-regid-with-publickey)
            * [2.5.2 RegID With Controller](#252-regid-with-controller)
            * [2.5.3 Revoke ID](#253-revoke-id)
            * [2.5.4 Revoke ID By Controller](#254-revoke-id-by-controller)
            * [2.5.5 Remove Controller](#255-remove-controller)
            * [2.5.6 RegID With Attributes](#256-regid-with-attributes)
            * [2.5.7 Add Key](#257-add-key)
            * [2.5.8 Add Key By Index](#258-add-key-by-index)
            * [2.5.9 Remove Key](#259-remove-key)
            * [2.5.10 Remove Key By Index](#2510-remove-key-by-index)
            * [2.5.11 Set Recovery](#2511-set-recovery)
            * [2.5.12 Update Recovery](#2512-update-recovery)
            * [2.5.13 Remove Recovery](#2513-remove-recovery)
            * [2.5.14 AddKey By Controller](#2514-addkey-by-controller)
            * [2.5.15 RemoveKey By Controller](#2515-removekey-by-controller)
            * [2.5.16 AddKey By Recovery](#2516-addkey-by-recovery)
            * [2.5.17 RemoveKey By Recovery](#2517-removekey-by-recovery)
            * [2.5.18 Add Attributes](#2518-add-attributes)
            * [2.5.19 Add Attributes By Index](#2519-add-attributes-by-index)
            * [2.5.20 Remove Attribute](#2520-remove-attribute)
            * [2.5.21 Remove Attribute By Index](#2521-remove-attribute-by-index)
            * [2.5.22 Add Attributes By Controller](#2522-add-attributes-by-controller)
            * [2.5.23 Remove Attributes By Controller](#2523-remove-attributes-by-controller)
            * [2.5.24 Add New AuthKey](#2524-add-new-authkey)
            * [2.5.25 Add NewAuth Key By Recovery](#2525-add-newauth-key-by-recovery)
            * [2.5.26 Add New AuthKey By Controller](#2526-add-new-authkey-by-controller)
            * [2.5.27 Set AuthKey](#2527-set-authkey)
            * [2.5.28 Set AuthKey By Recovery](#2528-set-authkey-by-recovery)
            * [2.5.29 Set AuthKey By Controller](#2529-set-authkey-by-controller)
            * [2.5.30 Remove AuthKey](#2530-remove-authkey)
            * [2.5.31 Remove AuthKey By Recovery](#2531-remove-authkey-by-recovery)
            * [2.5.32 Remove AuthKey By Controller](#2532-remove-authkey-by-controller)
            * [2.5.33 Add Service](#2533-add-service)
            * [2.5.34 Update Service](#2534-update-service)
            * [2.5.35 Remove Service](#2535-remove-service)
            * [2.5.36 Add Context](#2536-add-context)
            * [2.5.37 Remove Context](#2537-remove-context)
            * [2.5.38 Verify Signature](#2538-verify-signature)
            * [2.5.39 Verify Controller](#2539-verify-controller)
            * [2.5.40 Get PublicKeys Json](#2540-get-publickeys-json)
            * [2.5.41 Get Attributes Json](#2541-get-attributes-json)
            * [2.5.42 Get Attributes](#2542-get-attributes)
            * [2.5.43 Get Attribute ByKey](#2543-get-attribute-bykey)
            * [2.5.44 Get Service Json](#2544-get-service-json)
            * [2.5.45 Get KeyState](#2545-get-keystate)
            * [2.5.46 Get Controller Json](#2546-get-controller-json)
            * [2.5.47 Get Document Json](#2547-get-document-json)
		* [2.6 Credential API](#26-credential-api)
			* [2.6.1 Gen Sign Req](#261-gen-sign-req)
			* [2.6.2 Verify Sign Req](#262-verify-sign-req)
			* [2.6.3 Create Credential](#263-create-credential)
			* [2.6.4 Commit Credential](#264-commit-credential)
			* [2.6.5 Verify Credible OntId](#265-verify-credible-ontid)
			* [2.6.6 Verify Not Expired](#266-verify-not-expired)
			* [2.6.7 Verify Issuer Signature](#267-verify-issuer-signature)
			* [2.6.8 Verify Status](#268-verify-status)
			* [2.6.9 Create Presentation](#269-create-presentation)
			* [2.6.10 Verify Presentation](#2610-verify-presentation)
* [Contributing](#contributing)
	* [Website](#website)
	* [License](#license)

## 1. Overview
This is a comprehensive Go library for the Ontology blockchain. Currently, it supports local wallet management, digital asset management,  deployment/invoking of smart contracts and communication with the Ontology Blockchain. In the future it will also support more rich functions and applications.

## 2. How to use?

First, create an `OntologySDK` instance with the `NewOntologySdk` method.

```
ontSdk := NewOntologySdk()
```

Next, create an rpc, rest or websocket client.

```
ontSdk.NewRpcClient().SetAddress("http://localhost:20336")
```

Then, call the rpc server through the sdk instance.


### 2.1 Block Chain API

#### 2.1.1 Get current block height

```
ontSdk.GetCurrentBlockHeight() (uint32, error)
```

#### 2.1.2 Get current block hash

```
ontSdk.GetCurrentBlockHash() (common.Uint256, error)
```

#### 2.1.3 Get block by height

```
ontSdk.GetBlockByHeight(height uint32) (*types.Block, error)
```

#### 2.1.4 Get block by hash

```
ontSdk.GetBlockByHash(blockHash string) (*types.Block, error)
```

#### 2.1.5 Get transaction by transaction hash

```
ontSdk.GetTransaction(txHash string) (*types.Transaction, error)
```

#### 2.1.6 Get block hash by block height

```
ontSdk.GetBlockHash(height uint32) (common.Uint256, error)
```

#### 2.1.7 Get block height by transaction hash

```
ontSdk.GetBlockHeightByTxHash(txHash string) (uint32, error)
```

#### 2.1.8 Get transaction hashes of block by block height

```
ontSdk.GetBlockTxHashesByHeight(height uint32) (*sdkcom.BlockTxHashes, error)
```

#### 2.1.9 Get storage value of smart contract key

```
ontSdk.GetStorage(contractAddress string, key []byte) ([]byte, error)
```

#### 2.1.10 Get smart contract by contract address

```
ontSdk.GetSmartContract(contractAddress string) (*sdkcom.SmartContract, error)
```

#### 2.1.11 Get smart contract event by transaction hash

```
ontSdk.GetSmartContractEvent(txHash string) (*sdkcom.SmartContactEvent, error)
```

#### 2.1.12 Get all of smart contract events of block by block height

```
ontSdk.GetSmartContractEventByHeight(height uint32) ([]*sdkcom.SmartContactEvent, error)
```

#### 2.1.13 Get block merkle proof by transaction hash

```
ontSdk.GetMerkleProof(txHash string) (*sdkcom.MerkleProof, error)
```

#### 2.1.14 Get transaction state of transaction pool

```
ontSdk.GetMemPoolTxState(txHash string) (*sdkcom.MemPoolTxState, error)
```

#### 2.1.15 Get transaction count in transaction pool

```
ontSdk.GetMemPoolTxCount() (*sdkcom.MemPoolTxCount, error)
```

#### 2.1.16 Get version of Ontology

```
ontSdk.GetVersion() (string, error)
```

#### 2.1.17 Get network id of Ontology

```
ontSdk.GetNetworkId() (uint32, error)
```

#### 2.1.18 Send transaction to Ontology

```
ontSdk.SendTransaction(mutTx *types.MutableTransaction) (common.Uint256, error)
```

#### 2.19 Prepare execute transaction

```
ontSdk.PreExecTransaction(mutTx *types.MutableTransaction) (*sdkcom.PreExecResult, error)
```

### 2.2 Wallet API

#### 2.2.1 Create or Open Wallet

```
wa, err := OpenWallet(path string) (*Wallet, error)
```

If the path is for an existing wallet file, then open the wallet, otherwise return error.

#### 2.2.2 Save Wallet

```
wa.Save() error
```
Note that any modifications of the wallet require calling `Save()` in order for the changes to persist.

#### 2.2.3 New account

```
wa.NewAccount(keyType keypair.KeyType, curveCode byte, sigScheme s.SignatureScheme, passwd []byte) (*Account, error)
```

Ontology supports three type of keys: ecdsa, sm2 and ed25519, and support 224, 256, 384, 521 bits length of key in ecdsa, but only support 256 bits length of key in sm2 and ed25519.

Ontology support multiple signature scheme.

For ECDSA support SHA224withECDSA, SHA256withECDSA, SHA384withECDSA, SHA512withEdDSA, SHA3-224withECDSA, SHA3-256withECDSA, SHA3-384withECDSA, SHA3-512withECDSA, RIPEMD160withECDSA;

For SM2 support SM3withSM2, and for SHA512withEdDSA.

#### 2.2.4 New default setting account

```
wa.NewDefaultSettingAccount(passwd []byte) (*Account, error)
```

The default settings for an account uses ECDSA with SHA256withECDSA as signature scheme.

#### 2.2.5 New account from wif private key

```
wa.NewAccountFromWIF(wif, passwd []byte) (*Account, error)
```

#### 2.2.5 Delete account

```
wa.DeleteAccount(address string) error
```

#### 2.2.5 Get default account

```
wa.GetDefaultAccount(passwd []byte) (*Account, error)
```

#### 2.2.6 Set default account

```
wa.SetDefaultAccount(address string) error
```

#### 2.2.7 Get account by address

```
wa.GetAccountByAddress(address string, passwd []byte) (*Account, error)
```

#### 2.2.8 Get account by label

```
wa.GetAccountByLabel(label string, passwd []byte) (*Account, error)
```

#### 2.2.9 Get account by index

```
wa.GetAccountByIndex(index int, passwd []byte) (*Account, error)
```
Note that indexes start from 1.

#### 2.2.10 Get account count of wallet

```
wa.GetAccountCount() int
```

#### 2.2.11 Get default account data

```
wa.GetDefaultAccountData() (*AccountData, error)
```

#### 2.2.12 Get account data by address

```
wa.GetAccountDataByAddress(address string) (*AccountData, error)
```

#### 2.2.13 Get account data by label

```
wa.GetAccountDataByLabel(label string) (*AccountData, error)
```

#### 2.2.14 Get account data by index

```
wa.GetAccountDataByIndex(index int) (*AccountData, error)
```
Note that indexes start from 1.

#### 2.2.15 Set account label

```
wa.SetLabel(address, newLabel string) error
```

Note that label cannot duplicate.

#### 2.2.16 Set signature scheme of account

```
wa.SetSigScheme(address string, sigScheme s.SignatureScheme) error
```

#### 2.2.17 Change account password

```
wa.ChangeAccountPassword(address string, oldPassword, newPassword []byte) error
```

#### 2.2.18 Import account to wallet

```
wa.ImportAccounts(accountDatas []*AccountData, passwds [][]byte) error
```

#### 2.2.19 Export account to a new wallet

```
wa.ExportAccounts(path string, accountDatas []*AccountData, passwds [][]byte, newScrypts ...*keypair.ScryptParam) (*Wallet, error)
```

### 2.3 ONT Contract API

#### 2.3.1 Get balance

```
ontSdk.Native.Ont.BalanceOf(address common.Address) (uint64, error)
```

#### 2.3.2 Transfer

```
ontSdk.Native.Ont.Transfer(gasPrice, gasLimit uint64, from *Account, to common.Address, amount uint64) (common.Uint256, error)
```

#### 2.3.3 Multiple Transfer

```
ontSdk.Native.Ont.MultiTransfer(gasPrice, gasLimit uint64, states []*ont.State, signer *Account) (common.Uint256, error)
```

A multi transfer does more than one transfer of ONT in one transaction.

#### 2.3.4 Approve

```
ontSdk.Native.Ont.Approve(gasPrice, gasLimit uint64, from *Account, to common.Address, amount uint64) (common.Uint256, error)
```

#### 2.3.5 Approve Balance

```
ontSdk.Native.Ont.Allowance(from, to common.Address) (uint64, error)
```

#### 2.3.6 TransferFrom

```
ontSdk.Native.Ont.TransferFrom(gasPrice, gasLimit uint64, sender *Account, from, to common.Address, amount uint64) (common.Uint256, error)
```
#### 2.3.7 Get balance V2

```
ontSdk.Native.Ont.BalanceOfV2(address common.Address) (*big.Int, error)
```

#### 2.3.8 Transfer V2

```
ontSdk.Native.Ont.TransferV2(gasPrice, gasLimit uint64, from *Account, to common.Address, amount *big.Int) (common.Uint256, error)
```

#### 2.3.9 Multiple Transfer V2

```
ontSdk.Native.Ont.MultiTransferV2(gasPrice, gasLimit uint64, states []*ont.State, signer *Account) (common.Uint256, error)
```

A multi transfer does more than one transfer of ONT in one transaction.

#### 2.3.10 Approve V2

```
ontSdk.Native.Ont.ApproveV2(gasPrice, gasLimit uint64, from *Account, to common.Address, amount *big.Int) (common.Uint256, error)
```

#### 2.3.11 Allowance V2

```
ontSdk.Native.Ont.AllowanceV2(from, to common.Address) (*big.Int, error)
```

#### 2.3.12 Transfer From V2

```
ontSdk.Native.Ont.TransferFromV2(gasPrice, gasLimit uint64, sender *Account, from, to common.Address, amount *big.Int) (common.Uint256, error)
```

### 2.4 ONG Contract API


#### 2.4.1 Get balance

```
ontSdk.Native.Ong.BalanceOf(address common.Address) (uint64, error)
```

#### 2.4.2 Transfer

```
ontSdk.Native.Ong.Transfer(gasPrice, gasLimit uint64, from *Account, to common.Address, amount uint64) (common.Uint256, error)
```

#### 2.4.3 Multiple Transfer

```
ontSdk.Native.Ong.MultiTransfer(gasPrice, gasLimit uint64, states []*ont.State, signer *Account) (common.Uint256, error)
```

A multi transfer does more than one transfer of ONG in one transaction.

#### 2.4.4 Approve

```
ontSdk.Native.Ong.Approve(gasPrice, gasLimit uint64, from *Account, to common.Address, amount uint64) (common.Uint256, error)
```

#### 2.4.5 Approve Balance

```
ontSdk.Native.Ong.Allowance(from, to common.Address) (uint64, error)
```

#### 2.4.6 TransferFrom

```
ontSdk.Native.Ong.TransferFrom(gasPrice, gasLimit uint64, sender *Account, from, to common.Address, amount uint64) (common.Uint256, error)
```

#### 2.4.7 Withdraw ONG

```
ontSdk.Native.Ong.WithdrawONG(gasPrice, gasLimit uint64, address *Account, amount uint64) (common.Uint256, error)
```

#### 2.4.8 Get unbound ONG

```
ontSdk.Native.Ong.UnboundONG(address common.Address) (uint64, error)
```

#### 2.4.9 Get balance V2

```
ontSdk.Native.Ong.BalanceOfV2(address common.Address) (*big.Int, error)
```

#### 2.4.10 Transfer V2

```
ontSdk.Native.Ong.TransferV2(gasPrice, gasLimit uint64, from *Account, to common.Address, amount *big.Int) (common.Uint256, error)
```

#### 2.4.11 Multiple Transfer V2

```
ontSdk.Native.Ong.MultiTransferV2(gasPrice, gasLimit uint64, states []*ont.State, signer *Account) (common.Uint256, error)
```

A multi transfer does more than one transfer of ONG in one transaction.

#### 2.4.12 Approve V2

```
ontSdk.Native.Ong.ApproveV2(gasPrice, gasLimit uint64, from *Account, to common.Address, amount *big.Int) (common.Uint256, error)
```

#### 2.4.13 Approve Balance V2

```
ontSdk.Native.Ong.AllowanceV2(from, to common.Address) (*big.Int, error)
```

#### 2.4.14 TransferFrom V2

```
ontSdk.Native.Ong.TransferFrom(gasPrice, gasLimit uint64, sender *Account, from, to common.Address, amount *big.Int) (common.Uint256, error)
```

#### 2.4.15 Withdraw ONG V2

```
ontSdk.Native.Ong.WithdrawONG(gasPrice, gasLimit uint64, address *Account, amount *big.Int) (common.Uint256, error)
```

#### 2.4.16 Get unbound ONG V2

```
ontSdk.Native.Ong.UnboundONGV2(address common.Address) (*big.Int, error)
```
### 2.5 ONT ID API

#### 2.5.1 RegID With PublicKey

```
ontSdk.Native.OntId.RegIDWithPublicKey(gasPrice, gasLimit uint64, payer *Account, ontId string, signer *Account) (common.Uint256, error)
```
`ontId`: registered ONT ID

`signer`: public key of ONT ID and signer account

#### 2.5.2 RegID With Controller

```
ontSdk.Native.OntId.RegIDWithController(gasPrice, gasLimit uint64, payer *Account, ontId string, controller *ontid.Group, signers []ontid.Signer, controllerSigners []*Account) (common.Uint256, error)
```
`ontId`: registered ONT ID

`controller`:a group of ONT ID

`signers`: signer ONT IDs and its key index

`controllerSigners`: signer accounts

#### 2.5.3 Revoke ID

```
ontSdk.Native.OntId.RevokeID(gasPrice, gasLimit uint64, payer *Account, ontId string, index uint32, signer *Account) (common.Uint256, error)
```
`ontId`: revoked ONT ID

`index`: key index of ONT ID

`signer`: signer account

#### 2.5.4 Revoke ID By Controller

```
ontSdk.Native.OntId.RevokeIDByController(gasPrice, gasLimit uint64, payer *Account, ontId string, signers []ontid.Signer, controllerSigners []*Account) (common.Uint256, error)
```
`ontId`: revoked ONT ID

`signers`: signer ONT IDs and its key index

`controllerSigners`: signer accounts 

#### 2.5.5 Remove Controller

```
ontSdk.Native.OntId.RemoveController(gasPrice, gasLimit uint64, payer *Account, ontId string, index uint32, signer *Account) (common.Uint256, error)
```
`ontId`: ONT ID

`index`: key index of ONT ID

`signer`: signer account

#### 2.5.6 RegID With Attributes

```
ontSdk.Native.OntId.RegIDWithAttributes(gasPrice, gasLimit uint64, payer *Account, ontId string, attributes []*DDOAttribute, signer *Account) (common.Uint256, error)
```
`ontId`: registered ONT ID

`attributes`: attributes of ONT ID

`signer`: public key of ONT ID and signer account

#### 2.5.7 Add Key

```
ontSdk.Native.OntId.AddKey(gasPrice, gasLimit uint64, payer *Account, ontId string, newPubKey []byte, controller string, signer *Account) (common.Uint256, error)
```
`ontId`: ONT ID

`newPubKey`: new public key added

`controller`: controller ONT ID of this public key

`signer`: public key of ONT ID and signer account

#### 2.5.8 Add Key By Index

```
ontSdk.Native.OntId.AddKeyByIndex(gasPrice, gasLimit uint64, payer *Account, ontId string, newPubKey []byte, index uint32, controller string, signer *Account) (common.Uint256, error)
```
`ontId`: ONT ID

`newPubKey`: new public key added

`index`: key index of ONT ID

`controller`: controller ONT ID of this public key

`signer`: signer account

#### 2.5.9 Remove Key

```
ontSdk.Native.OntId.RemoveKey(gasPrice, gasLimit uint64, payer *Account, ontId string, removedPubKey []byte, signer *Account) (common.Uint256, error)
```
`ontId`: ONT ID

`removedPubKey`: public key removed

`signer`: public key of ONT ID and signer account

#### 2.5.10 Remove Key By Index

```
ontSdk.Native.OntId.RemoveKeyByIndex(gasPrice, gasLimit uint64, payer *Account, ontId string, removedPubKey []byte, index uint32, signer *Account) (common.Uint256, error)
```
`ontId`: ONT ID

`removedPubKey`: public key removed

`index`: key index of ONT ID

`signer`: signer account

#### 2.5.11 Set Recovery

```
ontSdk.Native.OntId.SetRecovery(gasPrice, gasLimit uint64, payer *Account, ontId string, recovery *ontid.Group, index uint32, signer *Account) (common.Uint256, error)
```
`ontId`: ONT ID

`recovery`: group of recovery of ONT ID

`index`: key index of ONT ID

`signer`: signer account

#### 2.5.12 Update Recovery

```
ontSdk.Native.OntId.UpdateRecovery(gasPrice, gasLimit uint64, payer *Account, ontId string, newRecovery *ontid.Group, signers []ontid.Signer, recoverySigners []*Account) (common.Uint256, error)
```
`ontId`: ONT ID

`newRecovery`: new group of recovery of ONT ID

`signers`: signer ONT IDs and its key index

`recoverySigners`: signer accounts

#### 2.5.13 Remove Recovery

```
ontSdk.Native.OntId.RemoveRecovery(gasPrice, gasLimit uint64, payer *Account, ontId string, index uint32, signer *Account) (common.Uint256, error)
```
`ontId`: ONT ID

`index`: key index of ONT ID

`signer`: signer account

#### 2.5.14 AddKey By Controller

```
ontSdk.Native.OntId.AddKeyByController(gasPrice, gasLimit uint64, payer *Account, ontId string, publicKey []byte, signers []ontid.Signer, controller string, controllerSigners []*Account) (common.Uint256, error)
```
`ontId`: ONT ID

`publicKey`: new public key of ONT ID

`signers`: signer ONT IDs and its key index

`controller`: controller ONT ID of this public key

`controllerSigners`: signer accounts

#### 2.5.15 RemoveKey By Controller

```
ontSdk.Native.OntId.RemoveKeyByController(gasPrice, gasLimit uint64, payer *Account, ontId string, publicKeyIndex []byte, signers []ontid.Signer, controllerSigners []*Account) (common.Uint256, error)
```
`ontId`: ONT ID

`publicKeyIndex`: public key index of ONT ID removed

`signers`: signer ONT IDs and its key index

`controllerSigners`: signer accounts

#### 2.5.16 AddKey By Recovery

```
ontSdk.Native.OntId.AddKeyByRecovery(gasPrice, gasLimit uint64, payer *Account, ontId string, publicKey []byte, signers []ontid.Signer, controller string, recoverySigners []*Account) (common.Uint256, error)
```
`ontId`: ONT ID

`publicKey`: new public key of ONT ID

`signers`: signer ONT IDs and its key index

`controller`: controller ONT ID of this public key

`recoverySigners`: signer accounts

#### 2.5.17 RemoveKey By Recovery

```
ontSdk.Native.OntId.RemoveKeyByRecovery(gasPrice, gasLimit uint64, payer *Account, ontId string, publicKeyIndex uint32, signers []ontid.Signer, recoverySigners []*Account) (common.Uint256, error)
```
`ontId`: ONT ID

`publicKeyIndex`: public key index of ONT ID removed

`signers`: signer ONT IDs and its key index

`recoverySigners`: signer accounts

#### 2.5.18 Add Attributes

```
ontSdk.Native.OntId.AddAttributes(gasPrice, gasLimit uint64, payer *Account, ontId string, attributes []*DDOAttribute, signer *Account) (common.Uint256, error)
``` 
`ontId`: ONT ID

`attributes`: attributes of ONT ID

`signer`: public key of ONT ID and signer account

#### 2.5.19 Add Attributes By Index

```
ontSdk.Native.OntId.AddAttributesByIndex(gasPrice, gasLimit uint64, payer *Account, ontId string, attributes []*DDOAttribute, index uint32, signer *Account) (common.Uint256, error)
```
`ontId`: ONT ID

`attributes`: attributes of ONT ID

`index`: key index of ONT ID

`signer`: signer account

#### 2.5.20 Remove Attribute

```
ontSdk.Native.OntId.RemoveAttribute(gasPrice, gasLimit uint64, payer *Account, ontId string, removeKey []byte, signer *Account) (common.Uint256, error)
```
`ontId`: ONT ID

`removeKey`: key of attribute want to remove

`signer`: public key of ONT ID and signer account

#### 2.5.21 Remove Attribute By Index

```
ontSdk.Native.OntId.RemoveAttributeByIndex(gasPrice, gasLimit uint64, payer *Account, ontId, removeKey []byte, index uint32, signer *Account) (common.Uint256, error)
```
`ontId`: ONT ID

`removeKey`: key of attribute want to remove

`index`: key index of ONT ID

`signer`: signer account

#### 2.5.22 Add Attributes By Controller

```
ontSdk.Native.OntId.AddAttributesByController(gasPrice, gasLimit uint64, payer *Account, ontId string, attributes []*DDOAttribute, signers []ontid.Signer, controllerSigners []*Account) (common.Uint256, error)
```
`ontId`: ONT ID

`attributes`: attributes of ONT ID

`signers`: signer ONT IDs and its key index

`controllerSigners`: signer accounts

#### 2.5.23 Remove Attributes By Controller

```
ontSdk.Native.OntId.RemoveAttributesByController(gasPrice, gasLimit uint64, payer *Account, ontId string, key []byte, signers []ontid.Signer, controllerSigners []*Account) (common.Uint256, error)
```
`ontId`: ONT ID

`key`: key of attribute want to remove

`signers`: signer ONT IDs and its key index

`controllerSigners`: signer accounts

#### 2.5.24 Add New AuthKey

```
ontSdk.Native.OntId.AddNewAuthKey(gasPrice, gasLimit uint64, payer *Account, ontId string, publicKey []byte, controller string, signIndex uint32, signer *Account) (common.Uint256, error)
```
`ontId`: ONT ID

`publicKey`:  public key of ONT ID

`controller`: controller ONT ID of this public key

`signIndex`: key index of ONT ID

`signer`: signer account

#### 2.5.25 Add NewAuth Key By Recovery

```
ontSdk.Native.OntId.AddNewAuthKeyByRecovery(gasPrice, gasLimit uint64, payer *Account, ontId string, publicKey []byte, controller string, signers []ontid.Signer, recoverySigners []*Account) (common.Uint256, error)
```
`ontId`: ONT ID

`publicKey`:  public key of ONT ID

`controller`: controller ONT ID of this public key

`signers`: signer ONT IDs and its key index

`recoverySigners`: signer accounts

#### 2.5.26 Add New AuthKey By Controller

```
ontSdk.Native.OntId.AddNewAuthKeyByController(gasPrice, gasLimit uint64, payer *Account, ontId string, publicKey []byte, controller string, signers []ontid.Signer, controllerSigners []*Account) (common.Uint256, error)

```
`ontId`: ONT ID

`publicKey`:  public key of ONT ID

`controller`: controller ONT ID of this public key

`signers`: signer ONT IDs and its key index

`controllerSigners`: signer accounts

#### 2.5.27 Set AuthKey

```
ontSdk.Native.OntId.SetAuthKey(gasPrice, gasLimit uint64, payer *Account, ontId string, index, signIndex uint32, signer *Account) (common.Uint256, error)
```
`ontId`: ONT ID

`index`:  key index of public key want to set to auth

`signIndex`: key index of ONT ID of signer

`signer`: signer account

#### 2.5.28 Set AuthKey By Recovery

```
ontSdk.Native.OntId.SetAuthKeyByRecovery(gasPrice, gasLimit uint64, payer *Account, ontId string, index uint32, signers []ontid.Signer, recoverySigners []*Account) (common.Uint256, error)
```
`ontId`: ONT ID

`index`:  key index of public key want to set to auth

`signers`: signer ONT IDs and its key index

`recoverySigners`: signer accounts

#### 2.5.29 Set AuthKey By Controller

```
ontSdk.Native.OntId.SetAuthKeyByController(gasPrice, gasLimit uint64, payer *Account, ontId string, index uint32, signers []ontid.Signer, controllerSigners []*Account) (common.Uint256, error)
```
`ontId`: ONT ID

`index`:  key index of public key want to set to auth

`signers`: signer ONT IDs and its key index

`controllerSigners`: signer accounts

#### 2.5.30 Remove AuthKey

```
ontSdk.Native.OntId.RemoveAuthKey(gasPrice, gasLimit uint64, payer *Account, ontId string, index uint32, signIndex uint32, signer *Account) (common.Uint256, error)
```
`ontId`: ONT ID

`index`:  key index of public key want to remove from auth

`signIndex`: key index of ONT ID of signer

`signer`: signer account

#### 2.5.31 Remove AuthKey By Recovery

```
ontSdk.Native.OntId.RemoveAuthKeyByRecovery(gasPrice, gasLimit uint64, payer *Account, ontId string, index uint32, signers []ontid.Signer, recoverySigners []*Account) (common.Uint256, error)
```
`ontId`: ONT ID

`index`:  key index of public key want to remove from auth

`signers`: signer ONT IDs and its key index

`recoverySigners`: signer accounts

#### 2.5.32 Remove AuthKey By Controller

```
ontSdk.Native.OntId.RemoveAuthKeyByController(gasPrice, gasLimit uint64, payer *Account, ontId string, index uint32, signers []ontid.Signer, controllerSigners []*Account) (common.Uint256, error)
```
`ontId`: ONT ID

`index`:  key index of public key want to remove from auth

`signers`: signer ONT IDs and its key index

`controllerSigners`: signer accounts

#### 2.5.33 Add Service

```
ontSdk.Native.OntId.AddService(gasPrice, gasLimit uint64, payer *Account, ontId string, serviceId, type_, serviceEndpint []byte, index uint32, signer *Account) (common.Uint256, error)
```
`ontId`: ONT ID

`serviceId`:  service Id

`type_`: service type

`serviceEndpint`: service endpint

`index`: key index of ONT ID

`signer`: signer account

#### 2.5.34 Update Service

```
ontSdk.Native.OntId.UpdateService(gasPrice, gasLimit uint64, payer *Account, ontId string, serviceId, type_, serviceEndpint []byte, index uint32, signer *Account) (common.Uint256, error)
```
`ontId`: ONT ID

`serviceId`:  service Id

`type_`: service type

`serviceEndpint`: service endpint

`index`: key index of ONT ID

`signer`: signer account

#### 2.5.35 Remove Service

```
ontSdk.Native.OntId.RemoveService(gasPrice, gasLimit uint64, payer *Account, ontId string, serviceId []byte, index uint32, signer *Account) (common.Uint256, error)
```
`ontId`: ONT ID

`serviceId`:  service Id want to remove

`index`: key index of ONT ID

`signer`: signer account

#### 2.5.36 Add Context

```
ontSdk.Native.OntId.AddContext(gasPrice, gasLimit uint64, payer *Account, ontId string, contexts [][]byte, index uint32, signer *Account) (common.Uint256, error)
```
`ontId`: ONT ID

`contexts`:  contexts want to add

`index`: key index of ONT ID

`signer`: signer account

#### 2.5.37 Remove Context

```
ontSdk.Native.OntId.RemoveContext(gasPrice, gasLimit uint64, payer *Account, ontId string, contexts [][]byte, index uint32, signer *Account) (common.Uint256, error)
```
`ontId`: ONT ID

`contexts`:  contexts want to remove

`index`: key index of ONT ID

`signer`: signer account

#### 2.5.38 Verify Signature

```
ontSdk.Native.OntId.VerifySignature(ontId string, keyIndex uint64, account *Account) (bool, error)
```
`ontId`: ONT ID

`keyIndex`: key index of ONT ID

`account`: signer account

#### 2.5.39 Verify Controller

```
ontSdk.Native.OntId.VerifyController(ontId string, signers []ontid.Signer, accounts []*Account) (bool, error)
```
`ontId`: ONT ID

`signers`: signer ONT IDs and its key index

`accounts`: signer accounts

#### 2.5.40 Get PublicKeys Json

```
ontSdk.Native.OntId.GetPublicKeysJson(ontId string) ([]byte, error)
```
`ontId`: ONT ID

#### 2.5.41 Get Attributes Json

```
ontSdk.Native.OntId.GetAttributesJson(ontId string) ([]byte, error)
```
`ontId`: ONT ID

#### 2.5.42 Get Attributes

```
ontSdk.Native.OntId.GetAttributes(ontId string) ([]byte, error)
```
`ontId`: ONT ID

#### 2.5.43 Get Attribute ByKey

```
ontSdk.Native.OntId.GetAttributeByKey(ontId, key string) ([]byte, error)
```
`ontId`: ONT ID

`key`: key of attribute want to query

#### 2.5.44 Get Service Json

```
ontSdk.Native.OntId.GetServiceJson(ontId string, serviceId string) ([]byte, error)
```
`ontId`: ONT ID

`serviceId`: service Id want to query

#### 2.5.45 Get KeyState

```
ontSdk.Native.OntId.GetKeyState(ontId string, keyIndex int) (string, error)
```
`ontId`: ONT ID

`keyIndex`: key index of ONT ID

#### 2.5.46 Get Controller Json

```
ontSdk.Native.OntId.GetControllerJson(ontId string) ([]byte, error)
```
`ontId`: ONT ID

#### 2.5.47 Get Document Json

```
ontSdk.Native.OntId.GetDocumentJson(ontId string) ([]byte, error)
```
`ontId`: ONT ID

### 2.6 Credential API

#### 2.6.1 Gen Sign Req

```
ontSdk.Credential.GenSignReq(credentialSubject interface{}, ontId string, signer *Account) (*Request, error)
```
`credentialSubject`: [credentialSubject of Credential](https://www.w3.org/TR/vc-data-model/#credential-subject)

`ontId`: holder ONT ID

`signer`: signer account

#### 2.6.2 Verify Sign Req

```
ontSdk.Credential.VerifySignReq(request *Request) error
```
`request`: result of GenSignReq

#### 2.6.3 Create Credential

```
ontSdk.Credential.CreateCredential(contexts []string, types []string, credentialSubject interface{}, issuerId string, expirationDateTimestamp int64, signer *Account) (*VerifiableCredential, uint32, error)
```
`contexts`: [definition](https://www.w3.org/TR/vc-data-model/#contexts)

`types`: [definition](https://www.w3.org/TR/vc-data-model/#types)

`credentialSubject`: [credentialSubject of Credential](https://www.w3.org/TR/vc-data-model/#credential-subject)

`issuerId`: ONT ID of issuer

`expirationDateTimestamp`: unix of expiration date timestamp

`signer`: signer account

#### 2.6.4 Commit Credential

```
ontSdk.Credential.CommitCredential(gasPrice, gasLimit uint64, credentialId, issuerId, holderId string, index uint32, signer, payer *Account) (common.Uint256, error)
```
`credentialId`: Id of credential

`issuerId`: ONT ID of issuer

`holderId`: ONT ID of holder

`index`: key index of issuer used to sign tx

`signer`: signer account

#### 2.6.5 Verify Credible OntId

```
ontSdk.Credential.VerifyCredibleOntId(credibleOntIds []string, credential *VerifiableCredential) error
```
`credibleOntIds`: credible ONT ID list

`credential`: [definition](https://www.w3.org/TR/vc-data-model/)

#### 2.6.6 Verify Not Expired

```
ontSdk.Credential.VerifyNotExpired(credential *VerifiableCredential) error
```
`credential`: [definition](https://www.w3.org/TR/vc-data-model/)

#### 2.6.7 Verify Issuer Signature

```
ontSdk.Credential.VerifyIssuerSignature(credential *VerifiableCredential) error
```
`credential`: [definition](https://www.w3.org/TR/vc-data-model/)

#### 2.6.8 Verify Status

```
ontSdk.Credential.VerifyStatus(credential *VerifiableCredential) error
```
`credential`: [definition](https://www.w3.org/TR/vc-data-model/)

#### 2.6.9 Create Presentation

```
ontSdk.Credential.CreatePresentation(credentials []*VerifiableCredential, contexts, types []string, holder string, signers []*Account) (*Presentation, error)
```
`credentials`: credential list

`contexts`: [definition](https://www.w3.org/TR/vc-data-model/#contexts)

`types`: [definition](https://www.w3.org/TR/vc-data-model/#types)

`holder`: ONTID of holder

`signers`: signer accounts

#### 2.6.10 Verify Presentation

```
ontSdk.Credential.VerifyPresentation(presentation *Presentation, credibleOntIds []string) error
```
`presentation`: [definition](https://www.w3.org/TR/vc-data-model/#presentations-0)

`credibleOntIds`: credible ONT ID list

# Contributing

Can I contribute patches to the Ontology project?

Yes! We appreciate your help!

Please open a pull request with signed-off commits. This means adding a line that
says "Signed-off-by: Name <email>" at the end of each commit, indicating that you
wrote the code and have the right to pass it on as an open source patch.
If you don't sign off your patches, we will not accept them.

You can also send your patches as emails to the developer mailing list.
Please join the Ontology mailing list or forum and talk to us about it.

Also, please write good git commit messages. A good commit message
looks like this:

  Header line: explain the commit in one line

  The body of the commit message should be a few lines of text, explaining things
  in more detail, possibly giving some background about the issue
  being fixed, etc.

  The body of the commit message can be several paragraphs long, and
  should use proper word-wrapping and keep the columns shorter than about
  74 characters or so. That way "git log" will show things
  nicely even when it's indented.

  Make sure you explain your solution and why you're doing what you're
  doing, and not just what you're doing. Reviewers (and your
  future self) can read the patch, but might not understand why a
  particular solution was implemented.

  Reported-by: whoever-reported-it
  Signed-off-by: Your Name <youremail@yourhost.com>

## Website

* https://ont.io/

## License

The Ontology library (i.e. all of the code outside of the cmd directory) is licensed under the GNU Lesser General Public License v3.0, also included in our repository in the License file.
