# ONI Golang SDK

ONI golang SDK implements the approach to the distribute storage network. The SDK includes a rest client that encapsulated [REST-API](api-docs.html) of ONI network and a SDK interface based the rest client.

## How to use

The ONI network consists of accounts, layer2 channel, storage spaces, and files. And before these, you need to run a synchronization node at your machine and open its' rest port, suppose the rest address is http://127.0.0.1:10335.

### Create account

Accessing the ONI network need requires an account. You can [new-account](oni_test.go#L72), or import a existed account by [wallet file](oni_test.go#L143) or [private key](oni_test.go#L150). After the account created, the account will be listened by synchronization node, and if you used a [synchronization instance(GUI wallet)](sorry, the link has not existed now), you can see the account detail.

You can export account from synchronization node to [wallet file](oni_test.go#L134) or [private key](oni_test.go#L122) to backup your account. You can also get the [current account info](oni_test.go#L89) and [log out your account](oni_test.go#L115) so that synchronization node no longer listens to your account.

### Test token faucet

After owning account, you should deposit some ONI to use ONI network. The testnet faucet list here:

> sorry, not open now

### Create a layer2 channel

ONI network used layer2 state channel to pay the fee of downloading file. So recommending user to create a layer2 channel before using ONI network.

> Please ensure block chain of your synchronization node catch the latest block of whole ONI network before using channel function.

Firstly, [open a channel](oni_test.go#L598) with partner(testnet partner is AcJdio7iRMzPxCWgBjSLSqKZcXMjNRtLpd or APnoekqXUkNDFQMbnnBCsMPQgmWoQQmsd4). Note that only one channel can be opend with the same partner. You can opened more than one channel at same time with different partner, and [switch channel](oni_test.go#L573) to use. You can [query current ued channel](oni_test.go#L564) and [query all channel](oni_test.go#L633), also you can check channel [is syncing](oni_test.go#L581) and [initialization progress](oni_test.go#L589).

After using channel, you can [deposit ONI to channel](oni_test.go#L624) and [withdraw ONI from it](oni_test.go#L615). If you don't want to use channel anymore, you can [close it](oni_test.go#L607).

### Downloading file

You can [download file](oni_test.go#L355) that other people shared to your synchronization node by using file link, hash, or share url. Note that the downloading is submit a downloading task to your synchronization node, there need some time to download complete file. You can get the [file info by using file url](oni_test.go#L402), and you can [get all download file info](oni_test.go#L412). Before downloading, you can set the download path by [updating config](oni_test.go#L687).

After you submit a download task, you can [pause](oni_test.go#L362), [resume](oni_test.go#L372) and [cancel](oni_test.go#L392) it. And if download failes, you can [retry download](oni_test.go#L382).

### Manage user space and upload file

ONI network enable user to [upload file](oni_test.go#L421). The file will take up the storage space of the whole network. The space includes two means: disk space and expired time. You can [upgrage space](oni_test.go#L271) first, and then upload file. Also you can use the [advanced upload mode](oni_test.go#L432) that upgrage space while uploading file.

Before upgrage space, you can [estimate the spend](oni_test.go#L288). And before file uploading, it can also [estimate spend](oni_test.go#L549). May be you need to [query user space](oni_test.go#L306) to ensure the space is enough. Or you want to [get all space chaning records](oni_test.go#L316). Not that the records existed in sync node local store, not at the chain. So if you clear your synchronization node data and restart it, the records will lost.

After you submit a upload task, you can [pause](oni_test.go#L447), [resume](oni_test.go#L460) and [cancel](oni_test.go#L486) it. And if upload failes, you can [retry upload](oni_test.go#L473). You can [query upload file info](oni_test.go#L511) by file hash and [query all upload file info](oni_test.go#L540). And you can [set the upload file white list when uploading file](oni_test.go#L430) and [query it](oni_test.go#L530), [update it](oni_test.go#L499) after it uploaded.

For the ONI network, you can [query the file storage setting](oni_test.go#L521).

### Transaction and file transfer records

Transaction means that transaction relate to asset transfer. File transfer means that file upload and download.

You can [send ONI token(only support ONI currentlly)] to other address, and [query this transaction event](oni_test.go#L169) to confirm transfer success. You can query [all transaction records](oni_test.go#L179) and [all events at specified block by height](oni_test.go#L190).

In the other hands, you can query the [file transafer detail](oni_test.go#L335) and [list](oni_test.go#L326), also you can [delete the complete transfer record](oni_test.go#L345).

### File crypto

ONI synchronization node also provide [encrypt](oni_test.go#L236) and [decrypt](oni_test.go#L243) file function. Note that the file should locate at synchronization node local storage, and the file path tha input to synchronization node should be absoulate path. The encrypted and decrypted file will overwrite the original file.

### Synchronization node manage

If your node lost connection, you can [specified the peer address that you want to connect and reconnect them](oni_test.go#L660). And, you can query [all dns info](oni_test.go#L670) and [all registered storage node num](oni_test.go#L679), these will help you to clear network status.

### Others

[Query network state](oni_test.go#L693), [get current height](oni_test.go#L702), [get synchronization version](oni_test.go#L710), [query current chain id](oni_test.go#L723), [query chain id list](oni_test.go#L731), [switch chain id](oni_test.go#L718).

> For more information, please reference the [rest-api docs](api-docs.html) and [sdk golang unit test code](oni_test.go)