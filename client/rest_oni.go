package client

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/ontio/ontology-go-sdk/client/oni"
	"github.com/ontio/ontology-go-sdk/common"
	"math/big"
	"net/url"
)

func (this *RestClient) NewAccount(req *oni.NewAccountReq) (*oni.NewAccountResp, error) {
	result := &oni.NewAccountResp{}
	if _, err := this.post(result, req, oni.URL_NEW_ACCOUNT); err != nil {
		return nil, fmt.Errorf("NewAccount: failed, err: %s", err)
	} else {
		return result, nil
	}
}

func (this *RestClient) CurrentAccount() (*oni.CurrentAccountResp, error) {
	result := &oni.CurrentAccountResp{}
	if _, err := this.get(result, oni.URL_CURRENT_ACCOUNT); err != nil {
		return nil, fmt.Errorf("CurrentAccount: failed, err: %s", err)
	} else {
		return result, nil
	}
}

func (this *RestClient) Logout(req *oni.LogoutReq) error {
	if _, err := this.post(nil, req, oni.URL_LOGOUT); err != nil {
		return fmt.Errorf("Logout: failed, err: %s", err)
	} else {
		return nil
	}
}

func (this *RestClient) ExportPrivKey(password string) (*oni.ExportPrivKeyResp, error) {
	result := &oni.ExportPrivKeyResp{}
	if _, err := this.get(result, oni.GenExportPrivKeyUrl(password)); err != nil {
		return nil, fmt.Errorf("ExportPrivKey: failed, err: %s", err)
	} else {
		return result, nil
	}
}

func (this *RestClient) ExportWalletFile() (*oni.ExportWalletResp, error) {
	result := &oni.ExportWalletResp{}
	if _, err := this.get(result, oni.URL_EXPORT_WALLET); err != nil {
		return nil, fmt.Errorf("ExportWalletFile: failed, err: %s", err)
	} else {
		return result, nil
	}
}

func (this *RestClient) ImportAccountWithWalletFile(req *oni.ImportAccWithWalletReq) error {
	if _, err := this.post(nil, req, oni.URL_IMPORT_WITH_WALLET); err != nil {
		return fmt.Errorf("ImportAccountWithWalletFile: failed, err: %s", err)
	} else {
		return nil
	}
}

func (this *RestClient) ImportAccountWithPrivKey(req *oni.ImportAccWithPrivKeyReq) error {
	if _, err := this.post(nil, req, oni.URL_IMPORT_WITH_PRIV_KEY); err != nil {
		return fmt.Errorf("ImportAccountWithPrivKey: failed, err: %s", err)
	} else {
		return nil
	}
}

func (this *RestClient) Balance(base58Addr string) (*oni.BalanceResp, error) {
	result := &oni.BalanceResp{}
	if _, err := this.get(result, oni.GenBalanceUrl(base58Addr)); err != nil {
		return nil, fmt.Errorf("Balance: failed, err: %s", err)
	} else {
		return result, nil
	}
}

func (this *RestClient) Transfer(req *oni.TransferReq) (txHash string, err error) {
	if restResult, err := this.post(nil, req, oni.URL_TRANSFER); err != nil {
		return "", fmt.Errorf("Transfer: failed, err: %s", err)
	} else {
		return string(restResult), nil
	}
}

func (this *RestClient) GetTxRecords(base58Addr string, transferType oni.TxType, asset string, limit uint64,
	height *uint64, skipTxCountFromBlock *string) (*oni.GetTxRecordsResp, error) {
	result := &oni.GetTxRecordsResp{}
	reqValues := &url.Values{}
	reqValues.Add("asset", asset)
	reqValues.Add("limit", fmt.Sprint(limit))
	if height != nil {
		reqValues.Add("height", fmt.Sprint(*height))
	}
	if skipTxCountFromBlock != nil {
		reqValues.Add("skipTxCountFromBlock", *skipTxCountFromBlock)
	}
	if _, err := this.get(result, oni.GenTxRecordsUrl(base58Addr, transferType), reqValues); err != nil {
		return nil, fmt.Errorf("GetTxRecords: failed, err: %s", err)
	} else {
		return result, nil
	}
}

func (this *RestClient) GetSCEventByTxHash(txHash string) ([]*common.SmartContactEvent, error) {
	result := make([]*common.SmartContactEvent, 0)
	if _, err := this.get(result, oni.GenSCEventByTxHashUrl(txHash)); err != nil {
		return nil, fmt.Errorf("GetSCEventByTxHash: failed, err: %s", err)
	} else {
		return result, nil
	}
}

func (this *RestClient) GetSCEventByHeight(height uint64) ([]*common.SmartContactEvent, error) {
	result := make([]*common.SmartContactEvent, 0)
	if _, err := this.get(result, oni.GenSCEventByHeightUrl(height)); err != nil {
		return nil, fmt.Errorf("GetSCEventByHeight: failed, err: %s", err)
	} else {
		return result, nil
	}
}

func (this *RestClient) PreExecSmartContract(req *oni.PreExecTxReq) (*oni.PreExecTxResp, error) {
	result := &oni.PreExecTxResp{}
	if _, err := this.post(result, req, oni.URL_PRE_EXEC_TX); err != nil {
		return nil, fmt.Errorf("PreExecSmartContract: failed, err: %s", err)
	} else {
		return result, nil
	}
}
func (this *RestClient) InvokeSmartContract(req *oni.InvokeSmartContractReq) (*oni.InvokeSmartContractResp, error) {
	result := &oni.InvokeSmartContractResp{}
	if _, err := this.post(result, req, oni.URL_INVOKE_SC); err != nil {
		return nil, fmt.Errorf("InvokeSmartContract: failed, err: %s", err)
	} else {
		return result, nil
	}
}

func (this *RestClient) Encrypt(req *oni.EncryptFileReq) error {
	if _, err := this.post(nil, req, oni.URL_ENCRYPT_FILE); err != nil {
		return fmt.Errorf("Encrypt: failed, err: %s", err)
	} else {
		return nil
	}
}

func (this *RestClient) Decrypt(req *oni.DecryptFileReq) error {
	if _, err := this.post(nil, req, oni.URL_DECRYPT_FILE); err != nil {
		return fmt.Errorf("Decrypt: failed, err: %s", err)
	} else {
		return nil
	}
}

func (this *RestClient) DeleteFile(req *oni.DeleteFileReq) (*oni.DeleteFileResp, error) {
	result := &oni.DeleteFileResp{}
	if _, err := this.post(nil, req, oni.URL_DELETE_FILE); err != nil {
		return nil, fmt.Errorf("DeleteFile: failed, err: %s", err)
	} else {
		return result, nil
	}
}

func (this *RestClient) DeleteFiles(req *oni.DeleteFilesReq) (*oni.DeleteFilesResp, error) {
	result := &oni.DeleteFilesResp{}
	if _, err := this.post(result, req, oni.URL_DELETE_FILES); err != nil {
		return nil, fmt.Errorf("DeleteFiles: failed, err: %s", err)
	} else {
		return result, nil
	}
}

func (this *RestClient) SetUserSpace(req *oni.SetUserSpaceReq) (*oni.SetUserSpaceResp, error) {
	result := &oni.SetUserSpaceResp{}
	if _, err := this.post(result, req, oni.URL_SET_USER_SPACE); err != nil {
		return nil, fmt.Errorf("SetUserSpace: failed, err: %s", err)
	} else {
		return result, nil
	}
}

func (this *RestClient) CostSetUserSpace(req *oni.CostSetUserSpaceReq) (*oni.CostSetUserSpaceResp, error) {
	result := &oni.CostSetUserSpaceResp{}
	if _, err := this.post(result, req, oni.URL_COST_SET_USER_SPACE); err != nil {
		return nil, fmt.Errorf("CostSetUserSpace: failed, err: %s", err)
	} else {
		return result, nil
	}
}

func (this *RestClient) GetUserSpace(base58Addr string) (*oni.GetUserSpaceResp, error) {
	result := &oni.GetUserSpaceResp{}
	if _, err := this.get(result, oni.GenGetUserSpaceUrl(base58Addr)); err != nil {
		return nil, fmt.Errorf("GetUserSpace: failed, err: %s", err)
	} else {
		return result, nil
	}
}

func (this *RestClient) GetUserSpaceRecords(base58Addr string, offset, limit uint64) (*oni.GetUserSpaceRecordsResp, error) {
	result := &oni.GetUserSpaceRecordsResp{}
	if _, err := this.get(result, oni.GenGetUserSpaceRecordsUrl(base58Addr, offset, limit)); err != nil {
		return nil, fmt.Errorf("GetUserSpaceRecords: failed, err: %s", err)
	} else {
		return result, nil
	}
}

func (this *RestClient) GetTransferList(transferType oni.TransferType, offset, limit uint64) (*oni.GetTransferListResp, error) {
	result := &oni.GetTransferListResp{}
	if _, err := this.get(result, oni.GenGetTransferListUrl(transferType, offset, limit)); err != nil {
		return nil, fmt.Errorf("GetTransferList: failed, err: %s", err)
	} else {
		return result, nil
	}
}

func (this *RestClient) GetTransferDetail(transferType oni.TransferType, transferId string) (*oni.GetTransferDetailResp, error) {
	result := &oni.GetTransferDetailResp{}
	hexId := hex.EncodeToString([]byte(transferId))
	if _, err := this.get(result, oni.GenGetTransferDetailUrl(transferType, hexId)); err != nil {
		return nil, fmt.Errorf("GetTransferDetail: failed, err: %s", err)
	} else {
		return result, nil
	}
}

func (this *RestClient) DeleteCompleteTask(req *oni.DeleteCompleteTaskReq) (*oni.DeleteCompleteTaskResp, error) {
	result := &oni.DeleteCompleteTaskResp{}
	if _, err := this.post(result, req, oni.URL_DELETE_COMPLETE_TASK); err != nil {
		return nil, fmt.Errorf("DeleteCompleteTask: failed, err: %s", err)
	} else {
		return result, nil
	}
}

func (this *RestClient) CommitDownloadTask(req *oni.CommitDownloadTaskReq) error {
	if _, err := this.post(nil, req, oni.URL_COMMIT_DOWNLOAD_TASK); err != nil {
		return fmt.Errorf("CommitDownloadTask: failed, err: %s", err)
	} else {
		return nil
	}
}

func (this *RestClient) DownloadPause(req *oni.DownloadPauseReq) (*oni.DownloadPauseResp, error) {
	result := &oni.DownloadPauseResp{}
	if _, err := this.post(result, req, oni.URL_DOWNLOAD_PAUSE); err != nil {
		return nil, fmt.Errorf("DownloadPause: failed, err: %s", err)
	} else {
		return result, nil
	}
}

func (this *RestClient) DownloadResume(req *oni.DownloadResumeReq) (*oni.DownloadResumeResp, error) {
	result := &oni.DownloadResumeResp{}
	if _, err := this.post(result, req, oni.URL_DOWNLOAD_RESUME); err != nil {
		return nil, fmt.Errorf("DownloadResume: failed, err: %s", err)
	} else {
		return result, nil
	}
}

func (this *RestClient) DownloadFailedRetry(req *oni.DownloadFailedRetryReq) (*oni.DownloadFailedRetryResp, error) {
	result := &oni.DownloadFailedRetryResp{}
	if _, err := this.post(result, req, oni.URL_DOWNLOAD_FAILED_RETRY); err != nil {
		return nil, fmt.Errorf("DownloadFailedRetry: failed, err: %s", err)
	} else {
		return result, nil
	}
}

func (this *RestClient) DownloadCancel(req *oni.DownloadCancelReq) (*oni.DownloadCancelResp, error) {
	result := &oni.DownloadCancelResp{}
	if _, err := this.post(result, req, oni.URL_DOWNLOAD_CANCEL); err != nil {
		return nil, fmt.Errorf("DownloadCancel: failed, err: %s", err)
	} else {
		return result, nil
	}
}

func (this *RestClient) GetDownloadInfo(url string) (*oni.GetDownloadInfoResp, error) {
	result := &oni.GetDownloadInfoResp{}
	hexUrl := hex.EncodeToString([]byte(url))
	if _, err := this.get(result, oni.GenGetDownloadInfoUrl(hexUrl)); err != nil {
		return nil, fmt.Errorf("GetDownloadInfo: failed, err: %s", err)
	} else {
		return result, nil
	}
}

func (this *RestClient) GetDownloadFileList(fileType oni.FileType, offset, limit uint64) (*oni.GetDownloadListResp, error) {
	result := &oni.GetDownloadListResp{}
	if _, err := this.get(result, oni.GenGetDownloadFileListUrl(fileType, offset, limit)); err != nil {
		return nil, fmt.Errorf("GetDownloadInfo: failed, err: %s", err)
	} else {
		return result, nil
	}
}

func (this *RestClient) CommitUploadTask(req *oni.CommitUploadTaskReq) (*oni.CommitUploadTaskResp, error) {
	result := &oni.CommitUploadTaskResp{}
	if _, err := this.post(result, req, oni.URL_COMMIT_UPLOAD_TASK); err != nil {
		return nil, fmt.Errorf("CommitUploadTask: failed, err: %s", err)
	} else {
		return result, nil
	}
}

func (this *RestClient) UploadPause(req *oni.UploadPauseReq) (*oni.UploadPauseResp, error) {
	result := &oni.UploadPauseResp{}
	if _, err := this.post(result, req, oni.URL_UPLOAD_PAUSE); err != nil {
		return nil, fmt.Errorf("UploadPause: failed, err: %s", err)
	} else {
		return result, nil
	}
}

func (this *RestClient) UploadResume(req *oni.UploadResumeReq) (*oni.UploadResumeResp, error) {
	result := &oni.UploadResumeResp{}
	if _, err := this.post(result, req, oni.URL_UPLOAD_RESUME); err != nil {
		return nil, fmt.Errorf("UploadResume: failed, err: %s", err)
	} else {
		return result, nil
	}
}

func (this *RestClient) UploadFailedRetry(req *oni.UploadFailedRetryReq) (*oni.UploadFailedRetryResp, error) {
	result := &oni.UploadFailedRetryResp{}
	if _, err := this.post(result, req, oni.URL_UPLOAD_FAILED_RETRY); err != nil {
		return nil, fmt.Errorf("UploadFailedRetry: failed, err: %s", err)
	} else {
		return result, nil
	}
}

func (this *RestClient) UploadCancel(req *oni.UploadCancelReq) (*oni.UploadCancelResp, error) {
	result := &oni.UploadCancelResp{}
	if _, err := this.post(result, req, oni.URL_UPLOAD_CANCEL); err != nil {
		return nil, fmt.Errorf("UploadCancel: failed, err: %s", err)
	} else {
		return result, nil
	}
}

func (this *RestClient) UpdateFileWhiteList(req *oni.UpdateFileWhiteListReq) (txHash string, err error) {
	if restData, err := this.post(nil, req, oni.URL_UPDATE_FILE_WHITE_LIST); err != nil {
		return "", fmt.Errorf("UpdateFileWhiteList: failed, err: %s", err)
	} else {
		return string(restData), nil
	}
}

func (this *RestClient) GetUploadFileInfo(fileHash string) (*oni.GetUploadFileInfoResp, error) {
	result := &oni.GetUploadFileInfoResp{}
	if _, err := this.get(result, oni.GenGetUploadFileInfoUrl(fileHash)); err != nil {
		return nil, fmt.Errorf("GetUploadFileInfo: failed, err: %s", err)
	} else {
		return result, nil
	}
}

func (this *RestClient) GetFSSetting() (*oni.GetFileStorageSettingResp, error) {
	result := &oni.GetFileStorageSettingResp{}
	if _, err := this.get(result, oni.URL_GET_FILE_STORAGE_SETTING); err != nil {
		return nil, fmt.Errorf("GetFSSetting: failed, err: %s", err)
	} else {
		return result, nil
	}
}

func (this *RestClient) GetFileWhiteList(fileHash string) ([]*oni.WhiteListAddress, error) {
	result := make([]*oni.WhiteListAddress, 0)
	if _, err := this.get(result, oni.URL_GET_FILE_WHITE_LIST); err != nil {
		return nil, fmt.Errorf("GetFileWhiteList: failed, err: %s", err)
	} else {
		return result, nil
	}
}

func (this *RestClient) GetUploadFileList(fileType oni.FileType, offset, limit uint64) (*oni.GetUploadFileListResp, error) {
	result := &oni.GetUploadFileListResp{}
	if _, err := this.get(result, oni.URL_GET_UPLOAD_FILE_LIST); err != nil {
		return nil, fmt.Errorf("GetUploadFileList: failed, err: %s", err)
	} else {
		return result, nil
	}
}

func (this *RestClient) GetUploadFileFee(filePath string, duration, proveInterval, copyNum, whiteListCount uint32,
	storeType oni.StorageType) (*oni.GetUploadFileFeeResp, error) {
	result := &oni.GetUploadFileFeeResp{}
	reqValues := &url.Values{}
	reqValues.Add("duration", fmt.Sprint(duration))
	reqValues.Add("interval", fmt.Sprint(proveInterval))
	reqValues.Add("copyNum", fmt.Sprint(copyNum))
	reqValues.Add("whitelistCount", fmt.Sprint(whiteListCount))
	reqValues.Add("storeType", fmt.Sprint(storeType))
	hexFilePath := hex.EncodeToString([]byte(filePath))
	if _, err := this.get(result, oni.GenGetUploadFileFeeUrl(hexFilePath)); err != nil {
		return nil, fmt.Errorf("GetUploadFileList: failed, err: %s", err)
	} else {
		return result, nil
	}
}

func (this *RestClient) CurrentChannel() (*oni.CurrentChannelResp, error) {
	result := &oni.CurrentChannelResp{}
	if _, err := this.get(result, oni.URL_CURRENT_CHANNEL); err != nil {
		return nil, fmt.Errorf("CurrentChannel: failed, err: %s", err)
	} else {
		return result, nil
	}
}

func (this *RestClient) SwitchChannel(req *oni.SwitchChannelReq) error {
	if _, err := this.post(nil, req, oni.URL_SWITCH_CHANNEL); err != nil {
		return fmt.Errorf("SwitchChannel: failed, err: %s", err)
	} else {
		return nil
	}
}

func (this *RestClient) ChannelIsSyncing() (bool, error) {
	result := &oni.ChannelIsSyncingResp{}
	if _, err := this.get(result, oni.URL_CHANNEL_IS_SYNCING); err != nil {
		return true, fmt.Errorf("CurrentChannel: failed, err: %s", err)
	} else {
		return result.Syncing, nil
	}
}

func (this *RestClient) ChannelInitProgress() (*oni.ChannelInitProgressResp, error) {
	result := &oni.ChannelInitProgressResp{}
	if _, err := this.get(result, oni.URL_CHANNEL_INIT_PROGRESS); err != nil {
		return nil, fmt.Errorf("ChannelInitProgress: failed, err: %s", err)
	} else {
		return result, nil
	}
}

func (this *RestClient) OpenChannel(req *oni.OpenChannelReq) error {
	if _, err := this.post(nil, req, oni.URL_OPEN_CHANNEL); err != nil {
		return fmt.Errorf("OpenChannel: failed, err: %s", err)
	} else {
		return nil
	}
}

func (this *RestClient) CloseChannel(req *oni.CloseChannelReq) error {
	if _, err := this.post(nil, req, oni.URL_CLOSE_CHANNEL); err != nil {
		return fmt.Errorf("CloseChannel: failed, err: %s", err)
	} else {
		return nil
	}
}

func (this *RestClient) WithdrawChannel(req *oni.WithdrawChannelReq) error {
	if _, err := this.post(nil, req, oni.URL_WITHDRAW_CHANNEL); err != nil {
		return fmt.Errorf("WithdrawChannel: failed, err: %s", err)
	} else {
		return nil
	}
}

func (this *RestClient) DepositChannel(req *oni.DepositChannelReq) error {
	if _, err := this.post(nil, req, oni.URL_DEPOSIT_CHANNEL); err != nil {
		return fmt.Errorf("DepositChannel: failed, err: %s", err)
	} else {
		return nil
	}
}

func (this *RestClient) GetAllChannels() (*oni.GetAllChannelsResp, error) {
	result := &oni.GetAllChannelsResp{}
	if _, err := this.get(result, oni.URL_GET_ALL_CHANNELS); err != nil {
		return nil, fmt.Errorf("GetAllChannels: failed, err: %s", err)
	} else {
		return result, nil
	}
}

func (this *RestClient) Revenue() (*oni.RevenueResp, error) {
	result := &oni.RevenueResp{}
	if _, err := this.get(result, oni.URL_REVENUE); err != nil {
		return nil, fmt.Errorf("Revenue: failed, err: %s", err)
	} else {
		return result, nil
	}
}

func (this *RestClient) MinerGetShardIncome(begin, end uint32, offset, limit uint64) (*oni.MinerGetShardIncomeResp, error) {
	result := &oni.MinerGetShardIncomeResp{}
	if _, err := this.get(result, oni.URL_MINER_GET_SHARE_INCOME); err != nil {
		return nil, fmt.Errorf("MinerGetShardIncome: failed, err: %s", err)
	} else {
		return result, nil
	}
}

func (this *RestClient) ReconnectPeer(req *oni.ReconnectPeerReq) (*oni.ReconnectPeerResp, error) {
	result := &oni.ReconnectPeerResp{}
	if _, err := this.post(result, req, oni.URL_RECONNECT_PEER); err != nil {
		return nil, fmt.Errorf("ReconnectPeer: failed, err: %s", err)
	} else {
		return result, nil
	}
}

func (this *RestClient) GetAllDns() (*oni.GetAllDNSResp, error) {
	result := &oni.GetAllDNSResp{}
	if _, err := this.get(result, oni.URL_GET_ALL_DNS); err != nil {
		return nil, fmt.Errorf("GetAllDns: failed, err: %s", err)
	} else {
		return result, nil
	}
}

func (this *RestClient) GetNodesInfo() (*oni.GetNodesInfoResp, error) {
	result := &oni.GetNodesInfoResp{}
	if _, err := this.get(result, oni.URL_GET_NODES_INFO); err != nil {
		return nil, fmt.Errorf("GetNodesInfo: failed, err: %s", err)
	} else {
		return result, nil
	}
}

func (this *RestClient) UpdateConfig(req *oni.UpdateConfigReq) error {
	if _, err := this.post(nil, req, oni.URL_UPDATE_CONFIG); err != nil {
		return fmt.Errorf("UpdateConfig: failed, err: %s", err)
	} else {
		return nil
	}
}

func (this *RestClient) NetworkState() (*oni.NetworkStateResp, error) {
	result := &oni.NetworkStateResp{}
	if _, err := this.get(result, oni.URL_NETWORK_STATE); err != nil {
		return nil, fmt.Errorf("NetworkState: failed, err: %s", err)
	} else {
		return result, nil
	}
}

func (this *RestClient) CurrentHeight() (uint64, error) {
	if restResult, err := this.get(nil, oni.URL_CURRENT_HEIGHT); err != nil {
		return 0, fmt.Errorf("CurrentHeight: failed, err: %s", err)
	} else {
		height := new(big.Int).SetBytes(restResult)
		return height.Uint64(), nil
	}
}

func (this *RestClient) Version() (string, error) {
	if restResult, err := this.get(nil, oni.URL_CURRENT_HEIGHT); err != nil {
		return "", fmt.Errorf("Version: failed, err: %s", err)
	} else {
		return string(restResult), nil
	}
}

// unimplemented
func (this *RestClient) ChainIdList() {

}

func (this *RestClient) SwitchChainId(req *oni.SwitchChainIdReq) error {
	if _, err := this.post(nil, req, oni.URL_UPDATE_CONFIG); err != nil {
		return fmt.Errorf("SwitchChainId: failed, err: %s", err)
	} else {
		return nil
	}
}

func (this *RestClient) ChainId() (string, error) {
	if restResult, err := this.get(nil, oni.URL_CURRENT_HEIGHT); err != nil {
		return "", fmt.Errorf("ChainId: failed, err: %s", err)
	} else {
		return string(restResult), nil
	}
}

func (this *RestClient) post(result interface{}, req interface{}, url string) ([]byte, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("post: marshal req failed, err: %s", err)
	}
	data, err := this.sendRestPostRequest(body, oni.URL_NEW_ACCOUNT)
	if err != nil {
		return nil, fmt.Errorf("post: send req failed, err: %s", err)
	}
	if restResult, err := handleRestResp(data, result); err != nil {
		return nil, fmt.Errorf("post: failed, err: %s", err)
	} else {
		return restResult, nil
	}
}

func (this *RestClient) get(result interface{}, url string, reqValues ...*url.Values) ([]byte, error) {
	data, err := this.sendRestGetRequest(url, reqValues...)
	if err != nil {
		return nil, fmt.Errorf("get: send req failed, err: %s", err)
	}
	if restResult, err := handleRestResp(data, result); err != nil {
		return nil, fmt.Errorf("get: failed, err: %s", err)
	} else {
		return restResult, nil
	}
}

func handleRestResp(data []byte, result interface{}) ([]byte, error) {
	restResp := &RestfulResp{}
	err := json.Unmarshal(data, restResp)
	if err != nil {
		return nil, fmt.Errorf("handleRestResp: unmarshal resp failed, err: %s", err)
	}
	if restResp.Error != REST_SUCCESS_CODE {
		return nil, fmt.Errorf("handleRestResp: resp failed, code %d, err: %s", restResp.Error, restResp.Desc)
	}
	if result != nil {
		return restResp.Result, nil
	}
	err = json.Unmarshal(restResp.Result, result)
	if err != nil {
		return restResp.Result, fmt.Errorf("handleRestResp: unmarshal result failed, err: %s", err)
	}
	return restResp.Result, nil
}
