package ontology_go_sdk

import (
	sdkcom "github.com/ontio/ontology-go-sdk/common"
	"github.com/ontio/ontology-go-sdk/utils"
	"github.com/ontio/ontology/account"
	"github.com/ontio/ontology/common"
	"github.com/ontio/ontology/core/types"
	httpcom "github.com/ontio/ontology/http/base/common"
	"github.com/ontio/ontology/smartcontract/service/native/ont"
	"fmt"
)

var (
	ONT_CONTRACT_ADDRESS, _ = utils.AddressFromHexString("0100000000000000000000000000000000000000")
	ONG_CONTRACT_ADDRESS, _ = utils.AddressFromHexString("0200000000000000000000000000000000000000")
)

var (
	ONT_CONTRACT_VERSION = byte(0)
	ONG_CONTRACT_VERSION = byte(0)
)

type NativeContract struct {
	ontSdk *OntologySdk
	Ont    *Ont
	Ong    *Ong
}

func newNativeContract(ontSdk *OntologySdk) *NativeContract {
	native := &NativeContract{ontSdk: ontSdk}
	native.Ont = &Ont{native: native, ontSdk: ontSdk}
	native.Ong = &Ong{native: native, ontSdk: ontSdk}
	return native
}

func (this *NativeContract) NewNativeInvokeTransaction(
	gasPrice,
	gasLimit uint64,
	version byte,
	contractAddress common.Address,
	method string,
	params []interface{},
) (*types.Transaction, error) {
	if params == nil {
		params = make([]interface{}, 0, 1)
	}
	//Params cannot empty, if params is empty, fulfil with empty string
	if len(params) == 0 {
		params = append(params, "")
	}
	invokeCode, err := httpcom.BuildNativeInvokeCode(contractAddress, version, method, params)
	if err != nil {
		return nil, fmt.Errorf("BuildNativeInvokeCode error:%s", err)
	}
	return sdkcom.NewInvokeTransaction(gasPrice, gasLimit, invokeCode), nil
}

func (this *NativeContract) InvokeNativeContract(
	gasPrice,
	gasLimit uint64,
	singer *account.Account,
	version byte,
	contractAddress common.Address,
	method string,
	params []interface{},
) (common.Uint256, error) {
	tx, err := this.NewNativeInvokeTransaction(gasPrice, gasLimit, version, contractAddress, method, params)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	err = this.ontSdk.SignToTransaction(tx, singer)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	return this.ontSdk.SendTransaction(tx)
}

func (this *NativeContract) PreExecInvokeNativeContract(
	contractAddress common.Address,
	version byte,
	method string,
	params []interface{},
) (*sdkcom.PreExecResult, error) {
	tx, err := this.NewNativeInvokeTransaction(0, 0, version, contractAddress, method, params)
	if err != nil {
		return nil, err
	}
	return this.ontSdk.PreExecTransaction(tx)
}

type Ont struct {
	ontSdk *OntologySdk
	native *NativeContract
}

func (this *Ont) NewTransferTransaction(gasPrice, gasLimit uint64, from, to common.Address, amount uint64) (*types.Transaction, error) {
	state := &ont.State{
		From:  from,
		To:    to,
		Value: amount,
	}
	return this.NewMultiTransferTransaction(gasPrice, gasLimit, []*ont.State{state})
}

func (this *Ont) Transfer(gasPrice, gasLimit uint64, from *account.Account, to common.Address, amount uint64) (common.Uint256, error) {
	tx, err := this.NewTransferTransaction(gasPrice, gasLimit, from.Address, to, amount)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	err = this.ontSdk.SignToTransaction(tx, from)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	return this.ontSdk.SendTransaction(tx)
}

func (this *Ont) NewMultiTransferTransaction(gasPrice, gasLimit uint64, states []*ont.State) (*types.Transaction, error) {
	return this.native.NewNativeInvokeTransaction(
		gasPrice,
		gasLimit,
		ONT_CONTRACT_VERSION,
		ONT_CONTRACT_ADDRESS,
		ont.TRANSFER_NAME,
		[]interface{}{states})
}

func (this *Ont) MultiTransfer(gasPrice, gasLimit uint64, states []*ont.State, signer *account.Account) (common.Uint256, error) {
	tx, err := this.NewMultiTransferTransaction(gasPrice, gasLimit, states)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	err = this.ontSdk.SignToTransaction(tx, signer)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	return this.ontSdk.SendTransaction(tx)
}

func (this *Ont) NewTransferFromTransaction(gasPrice, gasLimit uint64, sender, from, to common.Address, amount uint64) (*types.Transaction, error) {
	state := &ont.TransferFrom{
		Sender: sender,
		From:   from,
		To:     to,
		Value:  amount,
	}
	return this.native.NewNativeInvokeTransaction(
		gasPrice,
		gasLimit,
		ONT_CONTRACT_VERSION,
		ONT_CONTRACT_ADDRESS,
		ont.TRANSFERFROM_NAME,
		[]interface{}{state},
	)
}

func (this *Ont) TransferFrom(gasPrice, gasLimit uint64, sender *account.Account, from, to common.Address, amount uint64) (common.Uint256, error) {
	tx, err := this.NewTransferFromTransaction(gasPrice, gasLimit, sender.Address, from, to, amount)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	err = this.ontSdk.SignToTransaction(tx, sender)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	return this.ontSdk.SendTransaction(tx)
}

func (this *Ont) NewApproveTransaction(gasPrice, gasLimit uint64, from, to common.Address, amount uint64) (*types.Transaction, error) {
	state := &ont.State{
		From:  from,
		To:    to,
		Value: amount,
	}
	return this.native.NewNativeInvokeTransaction(
		gasPrice,
		gasLimit,
		ONT_CONTRACT_VERSION,
		ONT_CONTRACT_ADDRESS,
		ont.APPROVE_NAME,
		[]interface{}{state},
	)
}

func (this *Ont) Approve(gasPrice, gasLimit uint64, from *account.Account, to common.Address, amount uint64) (common.Uint256, error) {
	tx, err := this.NewApproveTransaction(gasPrice, gasLimit, from.Address, to, amount)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	err = this.ontSdk.SignToTransaction(tx, from)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	return this.ontSdk.SendTransaction(tx)
}

func (this *Ont) Allowance(from, to common.Address) (uint64, error) {
	type allowanceStruct struct {
		From common.Address
		To   common.Address
	}
	preResult, err := this.native.PreExecInvokeNativeContract(
		ONT_CONTRACT_ADDRESS,
		ONT_CONTRACT_VERSION,
		ont.ALLOWANCE_NAME,
		[]interface{}{&allowanceStruct{From: from, To: to}},
	)
	if err != nil {
		return 0, err
	}
	balance, err := preResult.Result.ToInteger()
	if err != nil {
		return 0, err
	}
	return balance.Uint64(), nil
}

func (this *Ont) Symbol() (string, error) {
	preResult, err := this.native.PreExecInvokeNativeContract(
		ONT_CONTRACT_ADDRESS,
		ONT_CONTRACT_VERSION,
		ont.SYMBOL_NAME,
		[]interface{}{},
	)
	if err != nil {
		return "", err
	}
	return preResult.Result.ToString()
}

func (this *Ont) BalanceOf(address common.Address) (uint64, error) {
	preResult, err := this.native.PreExecInvokeNativeContract(
		ONT_CONTRACT_ADDRESS,
		ONT_CONTRACT_VERSION,
		ont.BALANCEOF_NAME,
		[]interface{}{address[:]},
	)
	if err != nil {
		return 0, err
	}
	balance, err := preResult.Result.ToInteger()
	if err != nil {
		return 0, err
	}
	return balance.Uint64(), nil
}

func (this *Ont) Name() (string, error) {
	preResult, err := this.native.PreExecInvokeNativeContract(
		ONT_CONTRACT_ADDRESS,
		ONT_CONTRACT_VERSION,
		ont.NAME_NAME,
		[]interface{}{},
	)
	if err != nil {
		return "", err
	}
	return preResult.Result.ToString()
}

func (this *Ont) Decimals() (byte, error) {
	preResult, err := this.native.PreExecInvokeNativeContract(
		ONT_CONTRACT_ADDRESS,
		ONT_CONTRACT_VERSION,
		ont.DECIMALS_NAME,
		[]interface{}{},
	)
	if err != nil {
		return 0, err
	}
	decimals, err := preResult.Result.ToInteger()
	if err != nil {
		return 0, err
	}
	return byte(decimals.Uint64()), nil
}

func (this *Ont) TotalSupply() (uint64, error) {
	preResult, err := this.native.PreExecInvokeNativeContract(
		ONT_CONTRACT_ADDRESS,
		ONT_CONTRACT_VERSION,
		ont.TOTAL_SUPPLY_NAME,
		[]interface{}{},
	)
	if err != nil {
		return 0, err
	}
	balance, err := preResult.Result.ToInteger()
	if err != nil {
		return 0, err
	}
	return balance.Uint64(), nil
}

type Ong struct {
	ontSdk *OntologySdk
	native *NativeContract
}

func (this *Ong) NewTransferTransaction(gasPrice, gasLimit uint64, from, to common.Address, amount uint64) (*types.Transaction, error) {
	state := &ont.State{
		From:  from,
		To:    to,
		Value: amount,
	}
	return this.NewMultiTransferTransaction(gasPrice, gasLimit, []*ont.State{state})
}

func (this *Ong) Transfer(gasPrice, gasLimit uint64, from *account.Account, to common.Address, amount uint64) (common.Uint256, error) {
	tx, err := this.NewTransferTransaction(gasPrice, gasLimit, from.Address, to, amount)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	err = this.ontSdk.SignToTransaction(tx, from)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	return this.ontSdk.SendTransaction(tx)
}

func (this *Ong) NewMultiTransferTransaction(gasPrice, gasLimit uint64, states []*ont.State) (*types.Transaction, error) {
	return this.native.NewNativeInvokeTransaction(
		gasPrice,
		gasLimit,
		ONG_CONTRACT_VERSION,
		ONG_CONTRACT_ADDRESS,
		ont.TRANSFER_NAME,
		[]interface{}{states})
}

func (this *Ong) MultiTransfer(gasPrice, gasLimit uint64, states []*ont.State, signer *account.Account) (common.Uint256, error) {
	tx, err := this.NewMultiTransferTransaction(gasPrice, gasLimit, states)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	err = this.ontSdk.SignToTransaction(tx, signer)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	return this.ontSdk.SendTransaction(tx)
}

func (this *Ong) NewTransferFromTransaction(gasPrice, gasLimit uint64, sender, from, to common.Address, amount uint64) (*types.Transaction, error) {
	state := &ont.TransferFrom{
		Sender: sender,
		From:   from,
		To:     to,
		Value:  amount,
	}
	return this.native.NewNativeInvokeTransaction(
		gasPrice,
		gasLimit,
		ONG_CONTRACT_VERSION,
		ONG_CONTRACT_ADDRESS,
		ont.TRANSFERFROM_NAME,
		[]interface{}{state},
	)
}

func (this *Ong) TransferFrom(gasPrice, gasLimit uint64, sender *account.Account, from, to common.Address, amount uint64) (common.Uint256, error) {
	tx, err := this.NewTransferFromTransaction(gasPrice, gasLimit, sender.Address, from, to, amount)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	err = this.ontSdk.SignToTransaction(tx, sender)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	return this.ontSdk.SendTransaction(tx)
}

func (this *Ong) NewApproveTransaction(gasPrice, gasLimit uint64, from, to common.Address, amount uint64) (*types.Transaction, error) {
	state := &ont.State{
		From:  from,
		To:    to,
		Value: amount,
	}
	return this.native.NewNativeInvokeTransaction(
		gasPrice,
		gasLimit,
		ONG_CONTRACT_VERSION,
		ONG_CONTRACT_ADDRESS,
		ont.APPROVE_NAME,
		[]interface{}{state},
	)
}

func (this *Ong) Approve(gasPrice, gasLimit uint64, from *account.Account, to common.Address, amount uint64) (common.Uint256, error) {
	tx, err := this.NewApproveTransaction(gasPrice, gasLimit, from.Address, to, amount)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	err = this.ontSdk.SignToTransaction(tx, from)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	return this.ontSdk.SendTransaction(tx)
}

func (this *Ong) Allowance(from, to common.Address) (uint64, error) {
	type allowanceStruct struct {
		From common.Address
		To   common.Address
	}
	preResult, err := this.native.PreExecInvokeNativeContract(
		ONG_CONTRACT_ADDRESS,
		ONG_CONTRACT_VERSION,
		ont.ALLOWANCE_NAME,
		[]interface{}{&allowanceStruct{From: from, To: to}},
	)
	if err != nil {
		return 0, err
	}
	balance, err := preResult.Result.ToInteger()
	if err != nil {
		return 0, err
	}
	return balance.Uint64(), nil
}

func (this *Ong) Symbol() (string, error) {
	preResult, err := this.native.PreExecInvokeNativeContract(
		ONG_CONTRACT_ADDRESS,
		ONG_CONTRACT_VERSION,
		ont.SYMBOL_NAME,
		[]interface{}{},
	)
	if err != nil {
		return "", err
	}
	return preResult.Result.ToString()
}

func (this *Ong) BalanceOf(address common.Address) (uint64, error) {
	preResult, err := this.native.PreExecInvokeNativeContract(
		ONG_CONTRACT_ADDRESS,
		ONG_CONTRACT_VERSION,
		ont.BALANCEOF_NAME,
		[]interface{}{address[:]},
	)
	if err != nil {
		return 0, err
	}
	balance, err := preResult.Result.ToInteger()
	if err != nil {
		return 0, err
	}
	return balance.Uint64(), nil
}

func (this *Ong) Name() (string, error) {
	preResult, err := this.native.PreExecInvokeNativeContract(
		ONG_CONTRACT_ADDRESS,
		ONG_CONTRACT_VERSION,
		ont.NAME_NAME,
		[]interface{}{},
	)
	if err != nil {
		return "", err
	}
	return preResult.Result.ToString()
}

func (this *Ong) Decimals() (byte, error) {
	preResult, err := this.native.PreExecInvokeNativeContract(
		ONG_CONTRACT_ADDRESS,
		ONG_CONTRACT_VERSION,
		ont.DECIMALS_NAME,
		[]interface{}{},
	)
	if err != nil {
		return 0, err
	}
	decimals, err := preResult.Result.ToInteger()
	if err != nil {
		return 0, err
	}
	return byte(decimals.Uint64()), nil
}

func (this *Ong) TotalSupply() (uint64, error) {
	preResult, err := this.native.PreExecInvokeNativeContract(
		ONG_CONTRACT_ADDRESS,
		ONG_CONTRACT_VERSION,
		ont.TOTAL_SUPPLY_NAME,
		[]interface{}{},
	)
	if err != nil {
		return 0, err
	}
	balance, err := preResult.Result.ToInteger()
	if err != nil {
		return 0, err
	}
	return balance.Uint64(), nil
}
