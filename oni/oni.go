package oni

import (
	"encoding/hex"
	"fmt"
	"github.com/ontio/ontology-crypto/keypair"
	"github.com/ontio/ontology-crypto/signature"
	sdkComm "github.com/ontio/ontology-go-sdk/common"
	"github.com/ontio/ontology-go-sdk/oni/types"
	"github.com/ontio/ontology/common"
)

const (
	ONI_VERSION_BYTE   = byte(0)
	ONI_VERSION_STRING = "00"
)

type ONI struct {
	oniClient OniClient
}

func NewOni() *ONI {
	return &ONI{oniClient: NewOniRestClient()}
}

func (this *ONI) SetRestAddr(restAddr string) {
	rest, ok := this.oniClient.(*OniRestClient)
	if ok {
		rest.SetAddr(restAddr)
	}
}

func NewOniWithAddr(restAddr string) *ONI {
	rest := NewOniRestClient()
	rest.SetAddr(restAddr)
	return &ONI{oniClient: rest}
}

// create oni account, return account private key and wallet file json string
// only support create default keyType and curve account
// TODO: ensure keyType and curve corresponding params string
func (this *ONI) NewAccount(pwd, label string, scheme signature.SignatureScheme,
	createOnly bool) (keypair.PrivateKey, string, error) {
	req := &types.NewAccountReq{
		Password:   pwd,
		Label:      label,
		KeyType:    "ecdsa",
		Curve:      "P-256",
		Scheme:     scheme.Name(),
		CreateOnly: createOnly,
	}
	resp, err := this.oniClient.NewAccount(req)
	if err != nil {
		return nil, "", err
	}
	privKey, err := keypair.WIF2Key([]byte(resp.PrivateKey))
	if err != nil {
		return nil, "", fmt.Errorf("NewAccount: parse priv key failed, err: %s", err)
	}
	return privKey, resp.Wallet, nil
}

func (this *ONI) CurrentAccount() (privKey keypair.PrivateKey, pubKey keypair.PublicKey, addr common.Address,
	scheme signature.SignatureScheme, err error) {
	resp, err := this.oniClient.CurrentAccount()
	if err != nil {
		return
	}
	if resp.PrivateKey != "" {
		privKey, err = keypair.WIF2Key([]byte(resp.PrivateKey))
		if err != nil {
			err = fmt.Errorf("CurrentAccount: parse priv key failed, err: %s", err)
			return
		}
	}
	pubKeyData, err := hex.DecodeString(resp.PublicKey)
	if err != nil {
		err = fmt.Errorf("CurrentAccount: decode pub key data failed, err: %s", err)
		return
	}
	pubKey, err = keypair.DeserializePublicKey(pubKeyData)
	if err != nil {
		err = fmt.Errorf("CurrentAccount: deserialize pub key failed, err: %s", err)
		return
	}
	addr, err = common.AddressFromBase58(resp.Address)
	if err != nil {
		err = fmt.Errorf("CurrentAccount: decode addr failed, err: %s", err)
		return
	}
	scheme = resp.SigScheme
	return
}

func (this *ONI) Logout() error {
	return this.oniClient.Logout(&types.LogoutReq{})
}

func (this *ONI) ExportPrivKey(password string) (keypair.PrivateKey, error) {
	resp, err := this.oniClient.ExportPrivKey(password)
	if err != nil {
		return nil, err
	}
	privKey, err := keypair.WIF2Key([]byte(resp.PrivateKey))
	if err != nil {
		err = fmt.Errorf("ExportPrivKey: parse priv key failed, err: %s", err)
		return nil, err
	}
	return privKey, nil
}

func (this *ONI) ExportWalletFile() (string, error) {
	resp, err := this.oniClient.ExportWalletFile()
	if err != nil {
		return "", err
	}
	return resp.Wallet, nil
}

func (this *ONI) ImportWithWalletFile(walletString, password string) error {
	req := &types.ImportAccWithWalletReq{
		Wallet:   walletString,
		Password: password,
	}
	return this.oniClient.ImportAccountWithWalletFile(req)
}

func (this *ONI) ImportWithPrivateKey(privKey keypair.PrivateKey, password, label string) error {
	wif, err := keypair.Key2WIF(privKey)
	if err != nil {
		return fmt.Errorf("ImportWithPrivateKey: parse priv key to wif failed, err: %s", err)
	}
	req := &types.ImportAccWithPrivKeyReq{
		PrivateKey: string(wif),
		Password:   password,
		Label:      label,
	}
	return this.oniClient.ImportAccountWithPrivKey(req)
}

func (this *ONI) Balance(address common.Address) (*types.BalanceResp, error) {
	base58Addr := address.ToBase58()
	return this.oniClient.Balance(base58Addr)
}

// send asset to an account, return tx hash
// @params asset should be string, that is human readable, parsed by decimals
func (this *ONI) SendAsset(to common.Address, amount, asset, password string) (string, error) {
	req := &types.TransferReq{
		To:       to.ToBase58(),
		Asset:    asset,
		Amount:   amount,
		Password: password,
	}
	return this.oniClient.Transfer(req)
}

func (this *ONI) GetTxRecords(base58Addr string, transferType types.TxType, asset string, limit uint64,
	height *uint64, skipTxCountFromBlock *string) (types.GetTxRecordsResp, error) {
	return this.oniClient.GetTxRecords(base58Addr, transferType, asset, limit, height, skipTxCountFromBlock)
}

func (this *ONI) GetSCEventByTxHash(hash common.Uint256) (*sdkComm.SmartContactEvent, error) {
	return this.oniClient.GetSCEventByTxHash(hash.ToHexString())
}

func (this *ONI) GetSCEventByHeight(height uint64) ([]*sdkComm.SmartContactEvent, error) {
	return this.oniClient.GetSCEventByHeight(height)
}

func (this *ONI) PreExecSmartContract(contract common.Address, method string, params []interface{}) ([]byte, error) {
	req := &types.PreExecTxReq{
		Version:  ONI_VERSION_STRING,
		Contract: contract.ToHexString(),
		Method:   method,
		Params:   params,
	}
	resp, err := this.oniClient.PreExecSmartContract(req)
	if err != nil {
		return nil, err
	}
	result, err := hex.DecodeString(resp.Data)
	if err != nil {
		return nil, fmt.Errorf("PreExecSmartContract: decode result %s failed, err; %s", resp.Data, err)
	}
	return result, nil
}

// invoke smart contract and return tx hash
func (this *ONI) InvokeSmartContract(contract common.Address, method, password string, params []interface{}) (string, error) {
	req := &types.InvokeSmartContractReq{
		PreExecTxReq: types.PreExecTxReq{
			Version:  ONI_VERSION_STRING,
			Contract: contract.ToHexString(),
			Method:   method,
			Params:   params,
		},
		Password: password,
	}
	resp, err := this.oniClient.InvokeSmartContract(req)
	if err != nil {
		return "", err
	}
	return resp.Tx, nil
}

// encrypt file that locate at sync node
// @params path: file absolute path at sync node
// @params password: encrypt password, not account password
func (this *ONI) EncryptFile(path, password string) error {
	req := &types.EncryptFileReq{
		Path:     path,
		Password: password,
	}
	return this.oniClient.Encrypt(req)
}

func (this *ONI) DecryptFile(path, password string) error {
	req := &types.DecryptFileReq{
		EncryptFileReq: types.EncryptFileReq{
			Path:     path,
			Password: password,
		},
	}
	return this.oniClient.Decrypt(req)
}

// if uploaded file, delete it from saved node
// if download file, delete it from local
func (this *ONI) DeleteFile(fileHash string) (*types.DeleteFileResp, error) {
	req := &types.DeleteFileReq{Hash: fileHash}
	return this.oniClient.DeleteFile(req)
}

func (this *ONI) DeleteFiles(fileHashes []string) (*types.DeleteFilesResp, error) {
	req := &types.DeleteFilesReq{Hash: fileHashes}
	return this.oniClient.DeleteFiles(req)
}

func (this *ONI) SetUserSpace(account common.Address, sizeOperation *types.Operation, timeOperation *types.Operation,
	password string) (string, error) {
	req := &types.SetUserSpaceReq{
		CostSetUserSpaceReq: types.CostSetUserSpaceReq{
			Addr:   account.ToBase58(),
			Size:   sizeOperation,
			Second: timeOperation,
		},
		Password: password,
	}
	resp, err := this.oniClient.SetUserSpace(req)
	if err != nil {
		return "", err
	}
	return resp.Tx, nil
}

func (this *ONI) CostSetUserSpace(account common.Address, sizeOperation *types.Operation, timeOperation *types.Operation) (*types.CostSetUserSpaceResp, error) {
	req := &types.CostSetUserSpaceReq{
		Addr:   account.ToBase58(),
		Size:   sizeOperation,
		Second: timeOperation,
	}
	return this.oniClient.CostSetUserSpace(req)
}

func (this *ONI) GetUserSpace(account common.Address) (*types.GetUserSpaceResp, error) {
	return this.oniClient.GetUserSpace(account.ToBase58())
}

func (this *ONI) GetUserSpaceRecords(account common.Address, offset, limit uint64) ([]*types.UserSpaceRecord, error) {
	resp, err := this.oniClient.GetUserSpaceRecords(account.ToBase58(), offset, limit)
	if err != nil {
		return nil, err
	}
	return resp.Records, nil
}

func (this *ONI) GetTransferList(transferType types.TransferType, offset, limit uint64) (*types.GetTransferListResp, error) {
	return this.oniClient.GetTransferList(transferType, offset, limit)
}

func (this *ONI) GetTransferDetail(transferType types.TransferType, transferId string) (*types.GetTransferDetailResp, error) {
	return this.oniClient.GetTransferDetail(transferType, transferId)
}

func (this *ONI) DeleteCompleteTask(taskIds []string) (*types.DeleteCompleteTaskResp, error) {
	req := &types.DeleteCompleteTaskReq{Ids: taskIds}
	resp, err := this.oniClient.DeleteCompleteTask(req)
	if err != nil {
		return nil, err
	}
	return resp, err
}

// download file to sync node
// @params password: decrypt file password
func (this *ONI) DownloadFile(hash, url, link, password string, maxPeerNum uint32, setFileName bool) error {
	req := &types.CommitDownloadTaskReq{
		Hash:        hash,
		Url:         url,
		Link:        link,
		Password:    password,
		MaxPeerNum:  maxPeerNum,
		SetFileName: setFileName,
	}
	return this.oniClient.CommitDownloadTask(req)
}

func (this *ONI) DownloadPause(taskIds []string) ([]*types.Task, error) {
	req := &types.DownloadPauseReq{Ids: taskIds}
	resp, err := this.oniClient.DownloadPause(req)
	if err != nil {
		return nil, err
	}
	return resp.Tasks, nil
}

func (this *ONI) DownloadResume(taskIds []string) ([]*types.Task, error) {
	req := &types.DownloadResumeReq{DownloadPauseReq: types.DownloadPauseReq{Ids: taskIds}}
	resp, err := this.oniClient.DownloadResume(req)
	if err != nil {
		return nil, err
	}
	return resp.Tasks, nil
}

func (this *ONI) DownloadFailedRetry(taskIds []string) ([]*types.Task, error) {
	req := &types.DownloadFailedRetryReq{DownloadPauseReq: types.DownloadPauseReq{Ids: taskIds}}
	resp, err := this.oniClient.DownloadFailedRetry(req)
	if err != nil {
		return nil, err
	}
	return resp.Tasks, nil
}

func (this *ONI) DownloadCancel(taskIds []string) ([]*types.Task, error) {
	req := &types.DownloadCancelReq{DownloadPauseReq: types.DownloadPauseReq{Ids: taskIds}}
	resp, err := this.oniClient.DownloadCancel(req)
	if err != nil {
		return nil, err
	}
	return resp.Tasks, nil
}

func (this *ONI) GetDownloadFileInfo(url string) (*types.GetDownloadInfoResp, error) {
	return this.oniClient.GetDownloadFileInfo(url)
}

func (this *ONI) GetDownloadFileList(fileType types.FileType, offset, limit uint64) (*types.GetDownloadListResp, error) {
	return this.oniClient.GetDownloadFileList(fileType, offset, limit)
}

func (this *ONI) UploadFile(req *types.CommitUploadTaskReq) (*types.CommitUploadTaskResp, error) {
	return this.oniClient.CommitUploadTask(req)
}

func (this *ONI) UploadPause(taskIds []string) ([]*types.Task, error) {
	req := &types.UploadPauseReq{Ids: taskIds}
	resp, err := this.oniClient.UploadPause(req)
	if err != nil {
		return nil, err
	}
	return resp.Tasks, nil
}

func (this *ONI) UploadResume(taskIds []string) ([]*types.Task, error) {
	req := &types.UploadResumeReq{UploadPauseReq: types.UploadPauseReq{Ids: taskIds}}
	resp, err := this.oniClient.UploadResume(req)
	if err != nil {
		return nil, err
	}
	return resp.Tasks, nil
}

func (this *ONI) UploadFailedRetry(taskIds []string) ([]*types.Task, error) {
	req := &types.UploadFailedRetryReq{UploadPauseReq: types.UploadPauseReq{Ids: taskIds}}
	resp, err := this.oniClient.UploadFailedRetry(req)
	if err != nil {
		return nil, err
	}
	return resp.Tasks, nil
}

func (this *ONI) UploadCancel(taskIds []string) ([]*types.Task, error) {
	req := &types.UploadCancelReq{UploadPauseReq: types.UploadPauseReq{Ids: taskIds}}
	resp, err := this.oniClient.UploadCancel(req)
	if err != nil {
		return nil, err
	}
	return resp.Tasks, nil
}

func (this *ONI) UpdateFileWhiteList(fileHash string, operation types.WhiteListOperator,
	whiteList []*types.WhiteListAddress) (string, error) {
	req := &types.UpdateFileWhiteListReq{
		FileHash:  fileHash,
		Operation: operation,
		List:      whiteList,
	}
	return this.oniClient.UpdateFileWhiteList(req)
}

func (this *ONI) GetUploadFileInfo(fileHash string) (*types.GetUploadFileInfoResp, error) {
	return this.oniClient.GetUploadFileInfo(fileHash)
}

func (this *ONI) GetFSSetting() (*types.GetFileStorageSettingResp, error) {
	return this.oniClient.GetFSSetting()
}

func (this *ONI) GetFileWhiteList(fileHash string) ([]*types.WhiteListAddress, error) {
	return this.oniClient.GetFileWhiteList(fileHash)
}

func (this *ONI) GetUploadFileList(fileType types.FileType, offset, limit uint64) (*types.GetUploadFileListResp, error) {
	return this.oniClient.GetUploadFileList(fileType, offset, limit)
}

func (this *ONI) EstimateUploadFileFee(filePath string, duration, proveInterval, copyNum, whiteListCount uint32,
	storeType types.StorageType) (*types.GetUploadFileFeeResp, error) {
	return this.oniClient.GetUploadFileFee(filePath, duration, proveInterval, copyNum, whiteListCount, storeType)
}

func (this *ONI) GetCurrentChannel() (*types.Channel, error) {
	resp, err := this.oniClient.CurrentChannel()
	if err != nil {
		return nil, err
	}
	return resp.Channel, nil
}

func (this *ONI) SwitchChannel(partner common.Address, password string) error {
	req := &types.SwitchChannelReq{
		Partner:  partner.ToBase58(),
		Password: password,
	}
	return this.oniClient.SwitchChannel(req)
}

func (this *ONI) ChannelIsSyncing() (bool, error) {
	return this.oniClient.ChannelIsSyncing()
}

func (this *ONI) ChannelInitProgress() (*types.ChannelInitProgressResp, error) {
	return this.oniClient.ChannelInitProgress()
}

func (this *ONI) OpenChannel(partner common.Address, password string, amount string) error {
	req := &types.OpenChannelReq{
		SwitchChannelReq: types.SwitchChannelReq{
			Password: password,
			Partner:  partner.ToBase58(),
		},
		Amount: amount,
	}
	return this.oniClient.OpenChannel(req)
}

func (this *ONI) CloseChannel(partner common.Address, password string, amount string) error {
	req := &types.CloseChannelReq{
		SwitchChannelReq: types.SwitchChannelReq{
			Password: password,
			Partner:  partner.ToBase58(),
		},
	}
	return this.oniClient.CloseChannel(req)
}

func (this *ONI) WithdrawChannel(partner common.Address, password string, amount string) error {
	req := &types.WithdrawChannelReq{
		OpenChannelReq: types.OpenChannelReq{
			SwitchChannelReq: types.SwitchChannelReq{
				Password: password,
				Partner:  partner.ToBase58(),
			},
			Amount: amount,
		},
	}
	return this.oniClient.WithdrawChannel(req)
}

func (this *ONI) DepositChannel(partner common.Address, password string, amount string) error {
	req := &types.DepositChannelReq{
		OpenChannelReq: types.OpenChannelReq{
			SwitchChannelReq: types.SwitchChannelReq{
				Password: password,
				Partner:  partner.ToBase58(),
			},
			Amount: amount,
		},
	}
	return this.oniClient.DepositChannel(req)
}

func (this *ONI) GetAllChannels() (*types.GetAllChannelsResp, error) {
	return this.oniClient.GetAllChannels()
}

func (this *ONI) Revenue() (*types.RevenueResp, error) {
	return this.oniClient.Revenue()
}

func (this *ONI) MinerGetShardIncome(begin, end uint32, offset, limit uint64) (*types.MinerGetShardIncomeResp, error) {
	return this.oniClient.MinerGetShardIncome(begin, end, offset, limit)
}

func (this *ONI) ReconnectPeer(peers []string) ([]*types.Node, error) {
	req := &types.ReconnectPeerReq{Peers: peers}
	resp, err := this.oniClient.ReconnectPeer(req)
	if err != nil {
		return nil, err
	}
	return resp.Peers, nil
}

func (this *ONI) GetAllDns() (*types.GetAllDNSResp, error) {
	return this.oniClient.GetAllDns()
}

func (this *ONI) GetRegisteredStoreNodeNum() (uint64, error) {
	resp, err := this.oniClient.GetNodesInfo()
	if err != nil {
		return 0, err
	}
	return resp.Count, nil
}

func (this *ONI) UpdateConfig(req *types.UpdateConfigReq) error {
	return this.oniClient.UpdateConfig(req)
}

func (this *ONI) NetworkState() (*types.NetworkStateResp, error) {
	return this.oniClient.NetworkState()
}

func (this *ONI) CurrentHeight() (uint64, error) {
	return this.oniClient.CurrentHeight()
}

func (this *ONI) Version() (string, error) {
	return this.oniClient.Version()
}

func (this *ONI) SwitchChainId(chainId, config string) error {
	req := &types.SwitchChainIdReq{
		ChainId: chainId,
		Config:  config,
	}
	return this.oniClient.SwitchChainId(req)
}

func (this *ONI) ChainId() (string, error) {
	return this.oniClient.ChainId()
}
