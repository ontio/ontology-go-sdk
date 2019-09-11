package oni

import (
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/ontio/ontology-go-sdk/client"
	"github.com/ontio/ontology-go-sdk/common"
	"github.com/ontio/ontology-go-sdk/oni/types"
	"io/ioutil"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type OniRestClient struct {
	Addr       string
	restClient *http.Client
}

func NewOniRestClient() *OniRestClient {
	return &OniRestClient{
		restClient: &http.Client{
			Transport: &http.Transport{
				MaxIdleConnsPerHost:   5,
				DisableKeepAlives:     false,
				IdleConnTimeout:       time.Second * 300,
				ResponseHeaderTimeout: time.Second * 300,
				TLSClientConfig:       &tls.Config{InsecureSkipVerify: true},
			},
			Timeout: time.Second * 300,
		},
	}
}

func (self *OniRestClient) SetAddr(addr string) *OniRestClient {
	self.Addr = addr
	return self
}

func (self *OniRestClient) SetRestClient(restClient *http.Client) *OniRestClient {
	self.restClient = restClient
	return self
}

func (this *OniRestClient) NewAccount(req *types.NewAccountReq) (*types.NewAccountResp, error) {
	result := &types.NewAccountResp{}
	if _, err := this.post(result, req, types.URL_NEW_ACCOUNT); err != nil {
		return nil, fmt.Errorf("NewAccount: failed, err: %s", err)
	} else {
		return result, nil
	}
}

func (this *OniRestClient) CurrentAccount() (*types.CurrentAccountResp, error) {
	result := &types.CurrentAccountResp{}
	if _, err := this.get(result, types.URL_CURRENT_ACCOUNT); err != nil {
		return nil, fmt.Errorf("CurrentAccount: failed, err: %s", err)
	} else {
		return result, nil
	}
}

func (this *OniRestClient) Logout(req *types.LogoutReq) error {
	if _, err := this.post(nil, req, types.URL_LOGOUT); err != nil {
		return fmt.Errorf("Logout: failed, err: %s", err)
	} else {
		return nil
	}
}

func (this *OniRestClient) ExportPrivKey(password string) (*types.ExportPrivKeyResp, error) {
	result := &types.ExportPrivKeyResp{}
	if _, err := this.get(result, types.GenExportPrivKeyUrl(password)); err != nil {
		return nil, fmt.Errorf("ExportPrivKey: failed, err: %s", err)
	} else {
		return result, nil
	}
}

func (this *OniRestClient) ExportWalletFile() (*types.ExportWalletResp, error) {
	result := &types.ExportWalletResp{}
	if _, err := this.get(result, types.URL_EXPORT_WALLET); err != nil {
		return nil, fmt.Errorf("ExportWalletFile: failed, err: %s", err)
	} else {
		return result, nil
	}
}

func (this *OniRestClient) ImportAccountWithWalletFile(req *types.ImportAccWithWalletReq) error {
	if _, err := this.post(nil, req, types.URL_IMPORT_WITH_WALLET); err != nil {
		return fmt.Errorf("ImportAccountWithWalletFile: failed, err: %s", err)
	} else {
		return nil
	}
}

func (this *OniRestClient) ImportAccountWithPrivKey(req *types.ImportAccWithPrivKeyReq) error {
	if _, err := this.post(nil, req, types.URL_IMPORT_WITH_PRIV_KEY); err != nil {
		return fmt.Errorf("ImportAccountWithPrivKey: failed, err: %s", err)
	} else {
		return nil
	}
}

func (this *OniRestClient) Balance(base58Addr string) (*types.BalanceResp, error) {
	result := &types.BalanceResp{}
	if _, err := this.get(result, types.GenBalanceUrl(base58Addr)); err != nil {
		return nil, fmt.Errorf("Balance: failed, err: %s", err)
	} else {
		return result, nil
	}
}

func (this *OniRestClient) Transfer(req *types.TransferReq) (txHash string, err error) {
	if restResult, err := this.post(nil, req, types.URL_TRANSFER); err != nil {
		return "", fmt.Errorf("Transfer: failed, err: %s", err)
	} else {
		return string(restResult), nil
	}
}

func (this *OniRestClient) GetTxRecords(base58Addr string, transferType types.TxType, asset string, limit uint64,
	height *uint64, skipTxCountFromBlock *string) (types.GetTxRecordsResp, error) {
	result := &types.GetTxRecordsResp{}
	reqValues := &url.Values{}
	reqValues.Add("asset", asset)
	reqValues.Add("limit", fmt.Sprint(limit))
	if height != nil {
		reqValues.Add("height", fmt.Sprint(*height))
	}
	if skipTxCountFromBlock != nil {
		reqValues.Add("skipTxCountFromBlock", *skipTxCountFromBlock)
	}
	if _, err := this.get(result, types.GenTxRecordsUrl(base58Addr, transferType), reqValues); err != nil {
		return nil, fmt.Errorf("GetTxRecords: failed, err: %s", err)
	} else {
		return *result, nil
	}
}

func (this *OniRestClient) GetSCEventByTxHash(txHash string) (*common.SmartContactEvent, error) {
	result := &common.SmartContactEvent{}
	if _, err := this.get(result, types.GenSCEventByTxHashUrl(txHash)); err != nil {
		return nil, fmt.Errorf("GetSCEventByTxHash: failed, err: %s", err)
	} else {
		return result, nil
	}
}

func (this *OniRestClient) GetSCEventByHeight(height uint64) ([]*common.SmartContactEvent, error) {
	result := make([]*common.SmartContactEvent, 0)
	if _, err := this.get(&result, types.GenSCEventByHeightUrl(height)); err != nil {
		return nil, fmt.Errorf("GetSCEventByHeight: failed, err: %s", err)
	} else {
		return result, nil
	}
}

func (this *OniRestClient) PreExecSmartContract(req *types.PreExecTxReq) (*types.PreExecTxResp, error) {
	result := &types.PreExecTxResp{}
	if _, err := this.post(result, req, types.URL_PRE_EXEC_TX); err != nil {
		return nil, fmt.Errorf("PreExecSmartContract: failed, err: %s", err)
	} else {
		return result, nil
	}
}
func (this *OniRestClient) InvokeSmartContract(req *types.InvokeSmartContractReq) (*types.InvokeSmartContractResp, error) {
	result := &types.InvokeSmartContractResp{}
	if _, err := this.post(result, req, types.URL_INVOKE_SC); err != nil {
		return nil, fmt.Errorf("InvokeSmartContract: failed, err: %s", err)
	} else {
		return result, nil
	}
}

func (this *OniRestClient) Encrypt(req *types.EncryptFileReq) error {
	if _, err := this.post(nil, req, types.URL_ENCRYPT_FILE); err != nil {
		return fmt.Errorf("Encrypt: failed, err: %s", err)
	} else {
		return nil
	}
}

func (this *OniRestClient) Decrypt(req *types.DecryptFileReq) error {
	if _, err := this.post(nil, req, types.URL_DECRYPT_FILE); err != nil {
		return fmt.Errorf("Decrypt: failed, err: %s", err)
	} else {
		return nil
	}
}

func (this *OniRestClient) DeleteFile(req *types.DeleteFileReq) (*types.DeleteFileResp, error) {
	result := &types.DeleteFileResp{}
	if _, err := this.post(nil, req, types.URL_DELETE_FILE); err != nil {
		return nil, fmt.Errorf("DeleteFile: failed, err: %s", err)
	} else {
		return result, nil
	}
}

func (this *OniRestClient) DeleteFiles(req *types.DeleteFilesReq) (*types.DeleteFilesResp, error) {
	result := &types.DeleteFilesResp{}
	if _, err := this.post(result, req, types.URL_DELETE_FILES); err != nil {
		return nil, fmt.Errorf("DeleteFiles: failed, err: %s", err)
	} else {
		return result, nil
	}
}

func (this *OniRestClient) SetUserSpace(req *types.SetUserSpaceReq) (*types.SetUserSpaceResp, error) {
	result := &types.SetUserSpaceResp{}
	if _, err := this.post(result, req, types.URL_SET_USER_SPACE); err != nil {
		return nil, fmt.Errorf("SetUserSpace: failed, err: %s", err)
	} else {
		return result, nil
	}
}

func (this *OniRestClient) CostSetUserSpace(req *types.CostSetUserSpaceReq) (*types.CostSetUserSpaceResp, error) {
	result := &types.CostSetUserSpaceResp{}
	if _, err := this.post(result, req, types.URL_COST_SET_USER_SPACE); err != nil {
		return nil, fmt.Errorf("CostSetUserSpace: failed, err: %s", err)
	} else {
		return result, nil
	}
}

func (this *OniRestClient) GetUserSpace(base58Addr string) (*types.GetUserSpaceResp, error) {
	result := &types.GetUserSpaceResp{}
	if _, err := this.get(result, types.GenGetUserSpaceUrl(base58Addr)); err != nil {
		return nil, fmt.Errorf("GetUserSpace: failed, err: %s", err)
	} else {
		return result, nil
	}
}

func (this *OniRestClient) GetUserSpaceRecords(base58Addr string, offset, limit uint64) (*types.GetUserSpaceRecordsResp, error) {
	result := &types.GetUserSpaceRecordsResp{}
	if _, err := this.get(result, types.GenGetUserSpaceRecordsUrl(base58Addr, offset, limit)); err != nil {
		return nil, fmt.Errorf("GetUserSpaceRecords: failed, err: %s", err)
	} else {
		return result, nil
	}
}

func (this *OniRestClient) GetTransferList(transferType types.TransferType, offset, limit uint64) (*types.GetTransferListResp, error) {
	result := &types.GetTransferListResp{}
	if _, err := this.get(result, types.GenGetTransferListUrl(transferType, offset, limit)); err != nil {
		return nil, fmt.Errorf("GetTransferList: failed, err: %s", err)
	} else {
		return result, nil
	}
}

func (this *OniRestClient) GetTransferDetail(transferType types.TransferType, transferId string) (*types.GetTransferDetailResp, error) {
	result := &types.GetTransferDetailResp{}
	hexId := hex.EncodeToString([]byte(transferId))
	if _, err := this.get(result, types.GenGetTransferDetailUrl(transferType, hexId)); err != nil {
		return nil, fmt.Errorf("GetTransferDetail: failed, err: %s", err)
	} else {
		return result, nil
	}
}

func (this *OniRestClient) DeleteCompleteTask(req *types.DeleteCompleteTaskReq) (*types.DeleteCompleteTaskResp, error) {
	result := &types.DeleteCompleteTaskResp{}
	if _, err := this.post(result, req, types.URL_DELETE_COMPLETE_TASK); err != nil {
		return nil, fmt.Errorf("DeleteCompleteTask: failed, err: %s", err)
	} else {
		return result, nil
	}
}

func (this *OniRestClient) CommitDownloadTask(req *types.CommitDownloadTaskReq) error {
	if _, err := this.post(nil, req, types.URL_COMMIT_DOWNLOAD_TASK); err != nil {
		return fmt.Errorf("CommitDownloadTask: failed, err: %s", err)
	} else {
		return nil
	}
}

func (this *OniRestClient) DownloadPause(req *types.DownloadPauseReq) (*types.DownloadPauseResp, error) {
	result := &types.DownloadPauseResp{}
	if _, err := this.post(result, req, types.URL_DOWNLOAD_PAUSE); err != nil {
		return nil, fmt.Errorf("DownloadPause: failed, err: %s", err)
	} else {
		return result, nil
	}
}

func (this *OniRestClient) DownloadResume(req *types.DownloadResumeReq) (*types.DownloadResumeResp, error) {
	result := &types.DownloadResumeResp{}
	if _, err := this.post(result, req, types.URL_DOWNLOAD_RESUME); err != nil {
		return nil, fmt.Errorf("DownloadResume: failed, err: %s", err)
	} else {
		return result, nil
	}
}

func (this *OniRestClient) DownloadFailedRetry(req *types.DownloadFailedRetryReq) (*types.DownloadFailedRetryResp, error) {
	result := &types.DownloadFailedRetryResp{}
	if _, err := this.post(result, req, types.URL_DOWNLOAD_FAILED_RETRY); err != nil {
		return nil, fmt.Errorf("DownloadFailedRetry: failed, err: %s", err)
	} else {
		return result, nil
	}
}

func (this *OniRestClient) DownloadCancel(req *types.DownloadCancelReq) (*types.DownloadCancelResp, error) {
	result := &types.DownloadCancelResp{}
	if _, err := this.post(result, req, types.URL_DOWNLOAD_CANCEL); err != nil {
		return nil, fmt.Errorf("DownloadCancel: failed, err: %s", err)
	} else {
		return result, nil
	}
}

func (this *OniRestClient) GetDownloadFileInfo(url string) (*types.GetDownloadInfoResp, error) {
	result := &types.GetDownloadInfoResp{}
	hexUrl := hex.EncodeToString([]byte(url))
	if _, err := this.get(result, types.GenGetDownloadInfoUrl(hexUrl)); err != nil {
		return nil, fmt.Errorf("GetDownloadFileInfo: failed, err: %s", err)
	} else {
		return result, nil
	}
}

func (this *OniRestClient) GetDownloadFileList(fileType types.FileType, offset, limit uint64) (*types.GetDownloadListResp, error) {
	result := &types.GetDownloadListResp{}
	if _, err := this.get(result, types.GenGetDownloadFileListUrl(fileType, offset, limit)); err != nil {
		return nil, fmt.Errorf("GetDownloadFileList: failed, err: %s", err)
	} else {
		return result, nil
	}
}

func (this *OniRestClient) CommitUploadTask(req *types.CommitUploadTaskReq) (*types.CommitUploadTaskResp, error) {
	result := &types.CommitUploadTaskResp{}
	if _, err := this.post(result, req, types.URL_COMMIT_UPLOAD_TASK); err != nil {
		return nil, fmt.Errorf("CommitUploadTask: failed, err: %s", err)
	} else {
		return result, nil
	}
}

func (this *OniRestClient) UploadPause(req *types.UploadPauseReq) (*types.UploadPauseResp, error) {
	result := &types.UploadPauseResp{}
	if _, err := this.post(result, req, types.URL_UPLOAD_PAUSE); err != nil {
		return nil, fmt.Errorf("UploadPause: failed, err: %s", err)
	} else {
		return result, nil
	}
}

func (this *OniRestClient) UploadResume(req *types.UploadResumeReq) (*types.UploadResumeResp, error) {
	result := &types.UploadResumeResp{}
	if _, err := this.post(result, req, types.URL_UPLOAD_RESUME); err != nil {
		return nil, fmt.Errorf("UploadResume: failed, err: %s", err)
	} else {
		return result, nil
	}
}

func (this *OniRestClient) UploadFailedRetry(req *types.UploadFailedRetryReq) (*types.UploadFailedRetryResp, error) {
	result := &types.UploadFailedRetryResp{}
	if _, err := this.post(result, req, types.URL_UPLOAD_FAILED_RETRY); err != nil {
		return nil, fmt.Errorf("UploadFailedRetry: failed, err: %s", err)
	} else {
		return result, nil
	}
}

func (this *OniRestClient) UploadCancel(req *types.UploadCancelReq) (*types.UploadCancelResp, error) {
	result := &types.UploadCancelResp{}
	if _, err := this.post(result, req, types.URL_UPLOAD_CANCEL); err != nil {
		return nil, fmt.Errorf("UploadCancel: failed, err: %s", err)
	} else {
		return result, nil
	}
}

func (this *OniRestClient) UpdateFileWhiteList(req *types.UpdateFileWhiteListReq) (txHash string, err error) {
	if restData, err := this.post(nil, req, types.URL_UPDATE_FILE_WHITE_LIST); err != nil {
		return "", fmt.Errorf("UpdateFileWhiteList: failed, err: %s", err)
	} else {
		return string(restData), nil
	}
}

func (this *OniRestClient) GetUploadFileInfo(fileHash string) (*types.GetUploadFileInfoResp, error) {
	result := &types.GetUploadFileInfoResp{}
	if _, err := this.get(result, types.GenGetUploadFileInfoUrl(fileHash)); err != nil {
		return nil, fmt.Errorf("GetUploadFileInfo: failed, err: %s", err)
	} else {
		return result, nil
	}
}

func (this *OniRestClient) GetFSSetting() (*types.GetFileStorageSettingResp, error) {
	result := &types.GetFileStorageSettingResp{}
	if _, err := this.get(result, types.URL_GET_FILE_STORAGE_SETTING); err != nil {
		return nil, fmt.Errorf("GetFSSetting: failed, err: %s", err)
	} else {
		return result, nil
	}
}

func (this *OniRestClient) GetFileWhiteList(fileHash string) ([]*types.WhiteListAddress, error) {
	result := make([]*types.WhiteListAddress, 0)
	if _, err := this.get(result, types.URL_GET_FILE_WHITE_LIST); err != nil {
		return nil, fmt.Errorf("GetFileWhiteList: failed, err: %s", err)
	} else {
		return result, nil
	}
}

func (this *OniRestClient) GetUploadFileList(fileType types.FileType, offset, limit uint64) (*types.GetUploadFileListResp, error) {
	result := &types.GetUploadFileListResp{}
	if _, err := this.get(result, types.URL_GET_UPLOAD_FILE_LIST); err != nil {
		return nil, fmt.Errorf("GetUploadFileList: failed, err: %s", err)
	} else {
		return result, nil
	}
}

func (this *OniRestClient) GetUploadFileFee(filePath string, duration, proveInterval, copyNum, whiteListCount uint32,
	storeType types.StorageType) (*types.GetUploadFileFeeResp, error) {
	result := &types.GetUploadFileFeeResp{}
	reqValues := &url.Values{}
	reqValues.Add("duration", fmt.Sprint(duration))
	reqValues.Add("interval", fmt.Sprint(proveInterval))
	reqValues.Add("copyNum", fmt.Sprint(copyNum))
	reqValues.Add("whitelistCount", fmt.Sprint(whiteListCount))
	reqValues.Add("storeType", fmt.Sprint(storeType))
	hexFilePath := hex.EncodeToString([]byte(filePath))
	if _, err := this.get(result, types.GenGetUploadFileFeeUrl(hexFilePath)); err != nil {
		return nil, fmt.Errorf("GetUploadFileList: failed, err: %s", err)
	} else {
		return result, nil
	}
}

func (this *OniRestClient) CurrentChannel() (*types.CurrentChannelResp, error) {
	result := &types.CurrentChannelResp{}
	if _, err := this.get(result, types.URL_CURRENT_CHANNEL); err != nil {
		return nil, fmt.Errorf("CurrentChannel: failed, err: %s", err)
	} else {
		return result, nil
	}
}

func (this *OniRestClient) SwitchChannel(req *types.SwitchChannelReq) error {
	if _, err := this.post(nil, req, types.URL_SWITCH_CHANNEL); err != nil {
		return fmt.Errorf("SwitchChannel: failed, err: %s", err)
	} else {
		return nil
	}
}

func (this *OniRestClient) ChannelIsSyncing() (bool, error) {
	result := &types.ChannelIsSyncingResp{}
	if _, err := this.get(result, types.URL_CHANNEL_IS_SYNCING); err != nil {
		return true, fmt.Errorf("CurrentChannel: failed, err: %s", err)
	} else {
		return result.Syncing, nil
	}
}

func (this *OniRestClient) ChannelInitProgress() (*types.ChannelInitProgressResp, error) {
	result := &types.ChannelInitProgressResp{}
	if _, err := this.get(result, types.URL_CHANNEL_INIT_PROGRESS); err != nil {
		return nil, fmt.Errorf("ChannelInitProgress: failed, err: %s", err)
	} else {
		return result, nil
	}
}

func (this *OniRestClient) OpenChannel(req *types.OpenChannelReq) error {
	if _, err := this.post(nil, req, types.URL_OPEN_CHANNEL); err != nil {
		return fmt.Errorf("OpenChannel: failed, err: %s", err)
	} else {
		return nil
	}
}

func (this *OniRestClient) CloseChannel(req *types.CloseChannelReq) error {
	if _, err := this.post(nil, req, types.URL_CLOSE_CHANNEL); err != nil {
		return fmt.Errorf("CloseChannel: failed, err: %s", err)
	} else {
		return nil
	}
}

func (this *OniRestClient) WithdrawChannel(req *types.WithdrawChannelReq) error {
	if _, err := this.post(nil, req, types.URL_WITHDRAW_CHANNEL); err != nil {
		return fmt.Errorf("WithdrawChannel: failed, err: %s", err)
	} else {
		return nil
	}
}

func (this *OniRestClient) DepositChannel(req *types.DepositChannelReq) error {
	if _, err := this.post(nil, req, types.URL_DEPOSIT_CHANNEL); err != nil {
		return fmt.Errorf("DepositChannel: failed, err: %s", err)
	} else {
		return nil
	}
}

func (this *OniRestClient) GetAllChannels() (*types.GetAllChannelsResp, error) {
	result := &types.GetAllChannelsResp{}
	if _, err := this.get(result, types.URL_GET_ALL_CHANNELS); err != nil {
		return nil, fmt.Errorf("GetAllChannels: failed, err: %s", err)
	} else {
		return result, nil
	}
}

func (this *OniRestClient) Revenue() (*types.RevenueResp, error) {
	result := &types.RevenueResp{}
	if _, err := this.get(result, types.URL_REVENUE); err != nil {
		return nil, fmt.Errorf("Revenue: failed, err: %s", err)
	} else {
		return result, nil
	}
}

func (this *OniRestClient) MinerGetShardIncome(begin, end uint32, offset, limit uint64) (*types.MinerGetShardIncomeResp, error) {
	result := &types.MinerGetShardIncomeResp{}
	if _, err := this.get(result, types.URL_MINER_GET_SHARE_INCOME); err != nil {
		return nil, fmt.Errorf("MinerGetShardIncome: failed, err: %s", err)
	} else {
		return result, nil
	}
}

func (this *OniRestClient) ReconnectPeer(req *types.ReconnectPeerReq) (*types.ReconnectPeerResp, error) {
	result := &types.ReconnectPeerResp{}
	if _, err := this.post(result, req, types.URL_RECONNECT_PEER); err != nil {
		return nil, fmt.Errorf("ReconnectPeer: failed, err: %s", err)
	} else {
		return result, nil
	}
}

func (this *OniRestClient) GetAllDns() (*types.GetAllDNSResp, error) {
	result := &types.GetAllDNSResp{}
	if _, err := this.get(result, types.URL_GET_ALL_DNS); err != nil {
		return nil, fmt.Errorf("GetAllDns: failed, err: %s", err)
	} else {
		return result, nil
	}
}

func (this *OniRestClient) GetNodesInfo() (*types.GetNodesInfoResp, error) {
	result := &types.GetNodesInfoResp{}
	if _, err := this.get(result, types.URL_GET_NODES_INFO); err != nil {
		return nil, fmt.Errorf("GetNodesInfo: failed, err: %s", err)
	} else {
		return result, nil
	}
}

func (this *OniRestClient) UpdateConfig(req *types.UpdateConfigReq) error {
	if _, err := this.post(nil, req, types.URL_UPDATE_CONFIG); err != nil {
		return fmt.Errorf("UpdateConfig: failed, err: %s", err)
	} else {
		return nil
	}
}

func (this *OniRestClient) NetworkState() (*types.NetworkStateResp, error) {
	result := &types.NetworkStateResp{}
	if _, err := this.get(result, types.URL_NETWORK_STATE); err != nil {
		return nil, fmt.Errorf("NetworkState: failed, err: %s", err)
	} else {
		return result, nil
	}
}

func (this *OniRestClient) CurrentHeight() (uint64, error) {
	if restResult, err := this.get(nil, types.URL_CURRENT_HEIGHT); err != nil {
		return 0, fmt.Errorf("CurrentHeight: failed, err: %s", err)
	} else {
		height := new(big.Int).SetBytes(restResult)
		return height.Uint64(), nil
	}
}

func (this *OniRestClient) Version() (string, error) {
	if restResult, err := this.get(nil, types.URL_CURRENT_HEIGHT); err != nil {
		return "", fmt.Errorf("Version: failed, err: %s", err)
	} else {
		return string(restResult), nil
	}
}

// unimplemented
func (this *OniRestClient) ChainIdList() {

}

func (this *OniRestClient) SwitchChainId(req *types.SwitchChainIdReq) error {
	if _, err := this.post(nil, req, types.URL_UPDATE_CONFIG); err != nil {
		return fmt.Errorf("SwitchChainId: failed, err: %s", err)
	} else {
		return nil
	}
}

func (this *OniRestClient) ChainId() (string, error) {
	if restResult, err := this.get(nil, types.URL_CURRENT_HEIGHT); err != nil {
		return "", fmt.Errorf("ChainId: failed, err: %s", err)
	} else {
		return string(restResult), nil
	}
}

func (this *OniRestClient) post(result interface{}, req interface{}, url string) ([]byte, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("post: marshal req failed, err: %s", err)
	}
	data, err := this.sendRestPostRequest(this.Addr+url, body)
	if err != nil {
		return nil, fmt.Errorf("post: send req failed, err: %s", err)
	}
	if restResult, err := handleRestResp(data, result); err != nil {
		return nil, fmt.Errorf("post: failed, err: %s", err)
	} else {
		return restResult, nil
	}
}

func (self *OniRestClient) sendRestPostRequest(addr string, data []byte) ([]byte, error) {
	resp, err := self.restClient.Post(addr, "application/json", strings.NewReader(string(data)))
	if err != nil {
		return nil, fmt.Errorf("http post request:%s error:%s", data, err)
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read rest response body error:%s", err)
	}
	return body, nil
}

func (this *OniRestClient) get(result interface{}, url string, reqValues ...*url.Values) ([]byte, error) {
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

func (this *OniRestClient) sendRestGetRequest(reqPath string, values ...*url.Values) ([]byte, error) {
	reqUrl, err := this.getRequestUrl(reqPath, values...)
	if err != nil {
		return nil, err
	}
	resp, err := this.restClient.Get(reqUrl)
	if err != nil {
		return nil, fmt.Errorf("send http get request error:%s", err)
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read rest response body error:%s", err)
	}
	return body, nil
}

func (this *OniRestClient) getRequestUrl(reqPath string, values ...*url.Values) (string, error) {
	addr := this.Addr
	if !strings.HasPrefix(addr, "http") {
		addr = "http://" + addr
	}
	reqUrl, err := new(url.URL).Parse(addr)
	if err != nil {
		return "", fmt.Errorf("Parse address:%s error:%s", addr, err)
	}
	reqUrl.Path = reqPath
	if len(values) > 0 && values[0] != nil {
		reqUrl.RawQuery = values[0].Encode()
	}
	return reqUrl.String(), nil
}

func handleRestResp(data []byte, result interface{}) ([]byte, error) {
	restResp := &client.RestfulResp{}
	err := json.Unmarshal(data, restResp)
	if err != nil {
		return nil, fmt.Errorf("handleRestResp: unmarshal resp failed, err: %s", err)
	}
	if restResp.Error != client.REST_SUCCESS_CODE {
		return nil, fmt.Errorf("handleRestResp: resp failed, code %d, err: %s", restResp.Error, restResp.Desc)
	}
	if result == nil {
		return restResp.Result, nil
	}
	err = json.Unmarshal(restResp.Result, result)
	if err != nil {
		return restResp.Result, fmt.Errorf("handleRestResp: unmarshal result failed, err: %s", err)
	}
	return restResp.Result, nil
}
