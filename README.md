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
		* [2.4 ONG Contract API](#24-ong-contract-api)
			* [2.4.1 Get balance](#241-get-balance)
			* [2.4.2 Transfer](#242-transfer)
			* [2.4.3 Multiple Transfer](#243-multiple-transfer)
			* [2.4.4 Approve](#244-approve)
			* [2.4.5 Approve Balance](#245-approve-balance)
			* [2.4.6 TransferFrom](#246-transferfrom)
			* [2.4.7 Withdraw ONG](#247-withdraw-ong)
			* [2.4.8 Get unbound ONG](#248-get-unbound-ong)
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
