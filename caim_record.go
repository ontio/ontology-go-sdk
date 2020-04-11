package ontology_go_sdk

import (
	"fmt"
	"github.com/ontio/ontology/common"
	"io"
	"strconv"
)

var abi = "{\"hash\":\"0x36bb5c053b6b839c8f6b923fe852f91239b9fccc\",\"entrypoint\":\"Main\",\"functions\":[{\"name\":\"Main\",\"parameters\":[{\"name\":\"operation\",\"type\":\"String\"},{\"name\":\"args\",\"type\":\"Array\"}],\"returntype\":\"Any\"},{\"name\":\"Commit\",\"parameters\":[{\"name\":\"claimId\",\"type\":\"ByteArray\"},{\"name\":\"commiterId\",\"type\":\"ByteArray\"},{\"name\":\"ownerId\",\"type\":\"ByteArray\"}],\"returntype\":\"Boolean\"},{\"name\":\"Revoke\",\"parameters\":[{\"name\":\"claimId\",\"type\":\"ByteArray\"},{\"name\":\"ontId\",\"type\":\"ByteArray\"}],\"returntype\":\"Boolean\"},{\"name\":\"GetStatus\",\"parameters\":[{\"name\":\"claimId\",\"type\":\"ByteArray\"}],\"returntype\":\"ByteArray\"}],\"events\":[{\"name\":\"ErrorMsg\",\"parameters\":[{\"name\":\"id\",\"type\":\"ByteArray\"},{\"name\":\"error\",\"type\":\"String\"}],\"returntype\":\"Void\"},{\"name\":\"Push\",\"parameters\":[{\"name\":\"id\",\"type\":\"ByteArray\"},{\"name\":\"msg\",\"type\":\"String\"},{\"name\":\"args\",\"type\":\"ByteArray\"}],\"returntype\":\"Void\"}]}"

var contractAddress = "36bb5c053b6b839c8f6b923fe852f91239b9fccc"

type ClaimRecord struct {
	ContractAddress common.Address
	sdk             *OntologySdk
}

func NewClaimRecord(sdk *OntologySdk) *ClaimRecord {
	addr, _ := common.AddressFromHexString(contractAddress)
	return &ClaimRecord{
		ContractAddress: addr,
		sdk:             sdk,
	}
}

func (this *ClaimRecord) SendCommit(issuerOntid *Identity, pwd []byte, subjectOntid, claimId string,
	payerAcct *Account, gasPrice, gasLimit uint64) (common.Uint256, error) {
	if issuerOntid == nil || subjectOntid == "" || claimId == "" || payerAcct == nil {
		return common.UINT256_EMPTY, fmt.Errorf("param should not be nil")
	}
	tx, err := this.sdk.NeoVM.NewNeoVMInvokeTransaction(gasPrice, gasLimit, this.ContractAddress,
		[]interface{}{"Commit", []interface{}{[]byte(claimId), []byte(issuerOntid.ID), []byte(subjectOntid)}})
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	tx.Payer = payerAcct.Address
	//TODO
	controller, err := issuerOntid.GetControllerByIndex(1, pwd)
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

func (this *ClaimRecord) SendRevoke(issuerOntid *Identity, pwd []byte, claimId string, payerAcct *Account,
	gasLimit, gasPrice uint64) (common.Uint256, error) {
	if issuerOntid == nil || pwd == nil || claimId == "" || payerAcct == nil {
		return common.UINT256_EMPTY, fmt.Errorf("param should not be nil")
	}
	tx, err := this.sdk.NeoVM.NewNeoVMInvokeTransaction(gasPrice, gasLimit, this.ContractAddress, []interface{}{"Revoke", []interface{}{[]byte(claimId), []byte(issuerOntid.ID)}})
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	tx.Payer = payerAcct.Address
	controller, err := issuerOntid.GetControllerByIndex(1, pwd)
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
	var status = "00"
	if claimTx.Status != byte(0) {
		status = strconv.Itoa(int(claimTx.Status))
	}
	return string(claimTx.ClaimId) + "." + status + "." + string(claimTx.IssuerOntId) + "." + string(claimTx.SubjectOntId), nil
}

type ClaimTx struct {
	ClaimId      []byte
	IssuerOntId  []byte
	SubjectOntId []byte
	Status       byte
}

func (this *ClaimTx) Deserialize(source *common.ZeroCopySource) error {
	_, eof := source.NextByte()
	if eof {
		return io.ErrUnexpectedEOF
	}
	_, _, irregular, eof := source.NextVarUint()
	if irregular {
		return common.ErrIrregularData
	}
	if eof {
		return io.ErrUnexpectedEOF
	}
	_, eof = source.NextByte()
	if eof {
		return io.ErrUnexpectedEOF
	}
	claimId, err := readVarBytes(source)
	if err != nil {
		return err
	}
	_, eof = source.NextByte()
	if eof {
		return io.ErrUnexpectedEOF
	}
	issuerOntId, err := readVarBytes(source)
	if err != nil {
		return err
	}
	_, eof = source.NextByte()
	if eof {
		return io.ErrUnexpectedEOF
	}
	subjectOntId, err := readVarBytes(source)
	if err != nil {
		return err
	}
	_, eof = source.NextByte()
	if eof {
		return io.ErrUnexpectedEOF
	}
	status, eof := source.NextByte()
	if eof {
		return io.ErrUnexpectedEOF
	}
	this.ClaimId = claimId
	this.IssuerOntId = issuerOntId
	this.SubjectOntId = subjectOntId
	this.Status = status
	return nil
}

func readVarBytes(source *common.ZeroCopySource) ([]byte, error) {
	bs, _, irregular, eof := source.NextVarBytes()
	if irregular {
		return nil, common.ErrIrregularData
	}
	if eof {
		return nil, io.ErrUnexpectedEOF
	}
	return bs, nil
}
