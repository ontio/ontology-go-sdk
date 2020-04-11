package claim_record

import (
	"fmt"
	"github.com/ontio/ontology-go-sdk"
	"github.com/ontio/ontology/common"
)

var abi = "{\"hash\":\"0x36bb5c053b6b839c8f6b923fe852f91239b9fccc\",\"entrypoint\":\"Main\",\"functions\":[{\"name\":\"Main\",\"parameters\":[{\"name\":\"operation\",\"type\":\"String\"},{\"name\":\"args\",\"type\":\"Array\"}],\"returntype\":\"Any\"},{\"name\":\"Commit\",\"parameters\":[{\"name\":\"claimId\",\"type\":\"ByteArray\"},{\"name\":\"commiterId\",\"type\":\"ByteArray\"},{\"name\":\"ownerId\",\"type\":\"ByteArray\"}],\"returntype\":\"Boolean\"},{\"name\":\"Revoke\",\"parameters\":[{\"name\":\"claimId\",\"type\":\"ByteArray\"},{\"name\":\"ontId\",\"type\":\"ByteArray\"}],\"returntype\":\"Boolean\"},{\"name\":\"GetStatus\",\"parameters\":[{\"name\":\"claimId\",\"type\":\"ByteArray\"}],\"returntype\":\"ByteArray\"}],\"events\":[{\"name\":\"ErrorMsg\",\"parameters\":[{\"name\":\"id\",\"type\":\"ByteArray\"},{\"name\":\"error\",\"type\":\"String\"}],\"returntype\":\"Void\"},{\"name\":\"Push\",\"parameters\":[{\"name\":\"id\",\"type\":\"ByteArray\"},{\"name\":\"msg\",\"type\":\"String\"},{\"name\":\"args\",\"type\":\"ByteArray\"}],\"returntype\":\"Void\"}]}"

var contractAddress = "36bb5c053b6b839c8f6b923fe852f91239b9fccc"

type ClaimRecord struct {
	ContractAddress common.Address
	sdk             *ontology_go_sdk.OntologySdk
}

func NewClaimRecord(sdk *ontology_go_sdk.OntologySdk) *ClaimRecord {
	addr, _ := common.AddressFromHexString(contractAddress)
	return &ClaimRecord{
		ContractAddress: addr,
		sdk:             sdk,
	}
}

func (this *ClaimRecord) SendCommit(issuerOntid *ontology_go_sdk.Identity, pwd []byte, subjectOntid, claimId string,
	payerAcct *ontology_go_sdk.Account, gasPrice, gasLimit uint64) (common.Uint256, error) {
	if issuerOntid == nil || subjectOntid == "" || claimId == "" || payerAcct == nil {
		return common.UINT256_EMPTY, fmt.Errorf("param should not be nil")
	}
	tx, err := this.sdk.NeoVM.NewNeoVMInvokeTransaction(gasPrice, gasLimit, this.ContractAddress,
		[]interface{}{"Commit", []interface{}{[]byte(claimId), []byte(issuerOntid.ID), []byte(subjectOntid)}})
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	tx.Payer = payerAcct.Address
	controller, err := issuerOntid.GetControllerById(issuerOntid.ID, pwd)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	err = this.sdk.SignToTransaction(tx, controller)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	err = this.sdk.SignToTransaction(tx, payerAcct)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	return this.sdk.SendTransaction(tx)
}

func (this *ClaimRecord) SendRevoke(issuerOntid *ontology_go_sdk.Identity, pwd []byte, claimId string, payerAcct *ontology_go_sdk.Account,
	gasLimit, gasPrice uint64) (common.Uint256, error) {
	if issuerOntid == nil || pwd == nil || claimId == "" || payerAcct == nil {
		return common.UINT256_EMPTY, fmt.Errorf("param should not be nil")
	}
	tx, err := this.sdk.NeoVM.NewNeoVMInvokeTransaction(gasPrice, gasLimit, this.ContractAddress, []interface{}{"Revoke", []interface{}{[]byte(claimId), []byte(issuerOntid.ID)}})
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	tx.Payer = payerAcct.Address
	controller, err := issuerOntid.GetControllerById(issuerOntid.ID, pwd)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	err = this.sdk.SignToTransaction(tx, controller)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	err = this.sdk.SignToTransaction(tx, payerAcct)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	return this.sdk.SendTransaction(tx)
}

func (this *ClaimRecord) GetStatus(claimId string) (string, error) {
	if claimId == "" {
		return "", fmt.Errorf("claimid should not be nil")
	}
	res, err := this.sdk.NeoVM.PreExecInvokeNeoVMContract(this.ContractAddress, []interface{}{"GetStatus", []interface{}{[]byte(claimId)}})
	if err != nil {
		return "", err
	}
	result, err := res.Result.ToByteArray()
	if err != nil {
		return "", err
	}
	if result == nil {
		return "", nil
	}
	claimTx := &ClaimTx{}
	source := common.NewZeroCopySource(result)
	err = claimTx.Deserialize(source)
	if err != nil {
		return "", err
	}
	status := "00"
	if len(claimTx.Status) != 0 {
		status = string(claimTx.Status)
	}
	return string(claimTx.ClaimId) + "." + status + "." + string(claimTx.IssuerOntId) + "." + string(claimTx.SubjectOntId), nil
}
