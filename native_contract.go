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
package ontology_go_sdk

import (
	"fmt"
	"github.com/ontio/ontology-crypto/keypair"
	sdkcom "github.com/ontio/ontology-go-sdk/common"
	"github.com/ontio/ontology-go-sdk/utils"
	"github.com/ontio/ontology/common"
	"github.com/ontio/ontology/core/types"
	cutils "github.com/ontio/ontology/core/utils"
	"github.com/ontio/ontology/smartcontract/service/native/global_params"
	"github.com/ontio/ontology/smartcontract/service/native/ont"
	"github.com/ontio/ontology/smartcontract/service/native/ontid"
)

var (
	ONT_CONTRACT_ADDRESS, _           = utils.AddressFromHexString("0100000000000000000000000000000000000000")
	ONG_CONTRACT_ADDRESS, _           = utils.AddressFromHexString("0200000000000000000000000000000000000000")
	ONT_ID_CONTRACT_ADDRESS, _        = utils.AddressFromHexString("0300000000000000000000000000000000000000")
	GLOABL_PARAMS_CONTRACT_ADDRESS, _ = utils.AddressFromHexString("0400000000000000000000000000000000000000")
	AUTH_CONTRACT_ADDRESS, _          = utils.AddressFromHexString("0600000000000000000000000000000000000000")
	GOVERNANCE_CONTRACT_ADDRESS, _    = utils.AddressFromHexString("0700000000000000000000000000000000000000")
)

var (
	ONT_CONTRACT_VERSION           = byte(0)
	ONG_CONTRACT_VERSION           = byte(0)
	ONT_ID_CONTRACT_VERSION        = byte(0)
	GLOBAL_PARAMS_CONTRACT_VERSION = byte(0)
	AUTH_CONTRACT_VERSION          = byte(0)
	GOVERNANCE_CONTRACT_VERSION    = byte(0)
)

var OPCODE_IN_PAYLOAD = map[byte]bool{0xc6: true, 0x6b: true, 0x6a: true, 0xc8: true, 0x6c: true, 0x68: true, 0x67: true,
	0x7c: true, 0xc1: true}

type NativeContract struct {
	ontSdk       *OntologySdk
	Ont          *Ont
	Ong          *Ong
	OntId        *OntId
	GlobalParams *GlobalParam
	Auth         *Auth
}

func newNativeContract(ontSdk *OntologySdk) *NativeContract {
	native := &NativeContract{ontSdk: ontSdk}
	native.Ont = &Ont{native: native, ontSdk: ontSdk}
	native.Ong = &Ong{native: native, ontSdk: ontSdk}
	native.OntId = &OntId{native: native, ontSdk: ontSdk}
	native.GlobalParams = &GlobalParam{native: native, ontSdk: ontSdk}
	native.Auth = &Auth{native: native, ontSdk: ontSdk}
	return native
}

func (this *NativeContract) NewNativeInvokeTransaction(
	gasPrice,
	gasLimit uint64,
	version byte,
	contractAddress common.Address,
	method string,
	params []interface{},
) (*types.MutableTransaction, error) {
	if params == nil {
		params = make([]interface{}, 0, 1)
	}
	//Params cannot empty, if params is empty, fulfil with empty string
	if len(params) == 0 {
		params = append(params, "")
	}
	invokeCode, err := cutils.BuildNativeInvokeCode(contractAddress, version, method, params)
	if err != nil {
		return nil, fmt.Errorf("BuildNativeInvokeCode error:%s", err)
	}
	return this.ontSdk.NewInvokeTransaction(gasPrice, gasLimit, invokeCode), nil
}

func (this *NativeContract) InvokeNativeContract(
	gasPrice,
	gasLimit uint64,
	payer,
	singer *Account,
	version byte,
	contractAddress common.Address,
	method string,
	params []interface{},
) (common.Uint256, error) {
	tx, err := this.NewNativeInvokeTransaction(gasPrice, gasLimit, version, contractAddress, method, params)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	if payer != nil {
		this.ontSdk.SetPayer(tx, payer.Address)
		err = this.ontSdk.SignToTransaction(tx, payer)
		if err != nil {
			return common.UINT256_EMPTY, err
		}
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

func (this *Ont) NewTransferTransaction(gasPrice, gasLimit uint64, from, to common.Address, amount uint64) (*types.MutableTransaction, error) {
	state := &ont.State{
		From:  from,
		To:    to,
		Value: amount,
	}
	return this.NewMultiTransferTransaction(gasPrice, gasLimit, []*ont.State{state})
}

func (this *Ont) Transfer(gasPrice, gasLimit uint64, payer *Account, from *Account, to common.Address, amount uint64) (common.Uint256, error) {
	tx, err := this.NewTransferTransaction(gasPrice, gasLimit, from.Address, to, amount)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	if payer != nil {
		this.ontSdk.SetPayer(tx, payer.Address)
		err = this.ontSdk.SignToTransaction(tx, payer)
		if err != nil {
			return common.UINT256_EMPTY, err
		}
	}
	err = this.ontSdk.SignToTransaction(tx, from)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	return this.ontSdk.SendTransaction(tx)
}

func (this *Ont) NewMultiTransferTransaction(gasPrice, gasLimit uint64, states []*ont.State) (*types.MutableTransaction, error) {
	return this.native.NewNativeInvokeTransaction(
		gasPrice,
		gasLimit,
		ONT_CONTRACT_VERSION,
		ONT_CONTRACT_ADDRESS,
		ont.TRANSFER_NAME,
		[]interface{}{states})
}

func (this *Ont) MultiTransfer(gasPrice, gasLimit uint64, payer *Account, states []*ont.State, signer *Account) (common.Uint256, error) {
	tx, err := this.NewMultiTransferTransaction(gasPrice, gasLimit, states)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	if payer != nil {
		this.ontSdk.SetPayer(tx, payer.Address)
		err = this.ontSdk.SignToTransaction(tx, payer)
		if err != nil {
			return common.UINT256_EMPTY, err
		}
	}
	err = this.ontSdk.SignToTransaction(tx, signer)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	return this.ontSdk.SendTransaction(tx)
}

func (this *Ont) NewTransferFromTransaction(gasPrice, gasLimit uint64, sender, from, to common.Address, amount uint64) (*types.MutableTransaction, error) {
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

func (this *Ont) TransferFrom(gasPrice, gasLimit uint64, payer *Account, sender *Account, from, to common.Address, amount uint64) (common.Uint256, error) {
	tx, err := this.NewTransferFromTransaction(gasPrice, gasLimit, sender.Address, from, to, amount)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	if payer != nil {
		this.ontSdk.SetPayer(tx, payer.Address)
		err = this.ontSdk.SignToTransaction(tx, payer)
		if err != nil {
			return common.UINT256_EMPTY, err
		}
	}
	err = this.ontSdk.SignToTransaction(tx, sender)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	return this.ontSdk.SendTransaction(tx)
}

func (this *Ont) NewApproveTransaction(gasPrice, gasLimit uint64, from, to common.Address, amount uint64) (*types.MutableTransaction, error) {
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

func (this *Ont) Approve(gasPrice, gasLimit uint64, payer *Account, from *Account, to common.Address, amount uint64) (common.Uint256, error) {
	tx, err := this.NewApproveTransaction(gasPrice, gasLimit, from.Address, to, amount)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	if payer != nil {
		this.ontSdk.SetPayer(tx, payer.Address)
		err = this.ontSdk.SignToTransaction(tx, payer)
		if err != nil {
			return common.UINT256_EMPTY, err
		}
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

func (this *Ong) NewTransferTransaction(gasPrice, gasLimit uint64, from, to common.Address, amount uint64) (*types.MutableTransaction, error) {
	state := &ont.State{
		From:  from,
		To:    to,
		Value: amount,
	}
	return this.NewMultiTransferTransaction(gasPrice, gasLimit, []*ont.State{state})
}

func (this *Ong) Transfer(gasPrice, gasLimit uint64, payer *Account, from *Account, to common.Address, amount uint64) (common.Uint256, error) {
	tx, err := this.NewTransferTransaction(gasPrice, gasLimit, from.Address, to, amount)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	if payer != nil {
		this.ontSdk.SetPayer(tx, payer.Address)
		err = this.ontSdk.SignToTransaction(tx, payer)
		if err != nil {
			return common.UINT256_EMPTY, err
		}
	}
	err = this.ontSdk.SignToTransaction(tx, from)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	return this.ontSdk.SendTransaction(tx)
}

func (this *Ong) NewMultiTransferTransaction(gasPrice, gasLimit uint64, states []*ont.State) (*types.MutableTransaction, error) {
	return this.native.NewNativeInvokeTransaction(
		gasPrice,
		gasLimit,
		ONG_CONTRACT_VERSION,
		ONG_CONTRACT_ADDRESS,
		ont.TRANSFER_NAME,
		[]interface{}{states})
}

func (this *Ong) MultiTransfer(gasPrice, gasLimit uint64, states []*ont.State, signer *Account) (common.Uint256, error) {
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

func (this *Ong) NewTransferFromTransaction(gasPrice, gasLimit uint64, sender, from, to common.Address, amount uint64) (*types.MutableTransaction, error) {
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

func (this *Ong) TransferFrom(gasPrice, gasLimit uint64, payer *Account, sender *Account, from, to common.Address, amount uint64) (common.Uint256, error) {
	tx, err := this.NewTransferFromTransaction(gasPrice, gasLimit, sender.Address, from, to, amount)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	if payer != nil {
		this.ontSdk.SetPayer(tx, payer.Address)
		err = this.ontSdk.SignToTransaction(tx, payer)
		if err != nil {
			return common.UINT256_EMPTY, err
		}
	}
	err = this.ontSdk.SignToTransaction(tx, sender)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	return this.ontSdk.SendTransaction(tx)
}

func (this *Ong) NewWithdrawONGTransaction(gasPrice, gasLimit uint64, address common.Address, amount uint64) (*types.MutableTransaction, error) {
	return this.NewTransferFromTransaction(gasPrice, gasLimit, address, ONT_CONTRACT_ADDRESS, address, amount)
}

func (this *Ong) WithdrawONG(gasPrice, gasLimit uint64, payer *Account, address *Account, amount uint64) (common.Uint256, error) {
	tx, err := this.NewWithdrawONGTransaction(gasPrice, gasLimit, address.Address, amount)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	if payer != nil {
		this.ontSdk.SetPayer(tx, payer.Address)
		err = this.ontSdk.SignToTransaction(tx, payer)
		if err != nil {
			return common.UINT256_EMPTY, err
		}
	}
	err = this.ontSdk.SignToTransaction(tx, address)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	return this.ontSdk.SendTransaction(tx)
}

func (this *Ong) NewApproveTransaction(gasPrice, gasLimit uint64, from, to common.Address, amount uint64) (*types.MutableTransaction, error) {
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

func (this *Ong) Approve(gasPrice, gasLimit uint64, payer *Account, from *Account, to common.Address, amount uint64) (common.Uint256, error) {
	tx, err := this.NewApproveTransaction(gasPrice, gasLimit, from.Address, to, amount)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	if payer != nil {
		this.ontSdk.SetPayer(tx, payer.Address)
		err = this.ontSdk.SignToTransaction(tx, payer)
		if err != nil {
			return common.UINT256_EMPTY, err
		}
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

func (this *Ong) UnboundONG(address common.Address) (uint64, error) {
	return this.Allowance(ONT_CONTRACT_ADDRESS, address)
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

type OntId struct {
	ontSdk *OntologySdk
	native *NativeContract
}

func (this *OntId) NewRegIDWithPublicKeyTransaction(gasPrice, gasLimit uint64, ontId string,
	access string, proof []byte, pubKey keypair.PublicKey) (*types.MutableTransaction, error) {
	type regIDWithPublicKey struct {
		OntId  string
		PubKey []byte
		Access string
		Proof  []byte
	}
	return this.native.NewNativeInvokeTransaction(
		gasPrice,
		gasLimit,
		ONT_ID_CONTRACT_VERSION,
		ONT_ID_CONTRACT_ADDRESS,
		"regIDWithPublicKey",
		[]interface{}{
			&regIDWithPublicKey{
				OntId:  ontId,
				PubKey: keypair.SerializePublicKey(pubKey),
				Access: access,
				Proof:  proof,
			},
		},
	)
}

func (this *OntId) RegIDWithPublicKey(gasPrice, gasLimit uint64, payer *Account, signer *Account, ontId string,
	access string, proof []byte, pk *Account) (common.Uint256, error) {
	tx, err := this.NewRegIDWithPublicKeyTransaction(gasPrice, gasLimit, ontId, access, proof, pk.PublicKey)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	if payer != nil {
		this.ontSdk.SetPayer(tx, payer.Address)
		err = this.ontSdk.SignToTransaction(tx, payer)
		if err != nil {
			return common.UINT256_EMPTY, err
		}
	}
	err = this.ontSdk.SignToTransaction(tx, signer)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	err = this.ontSdk.SignToTransaction(tx, pk)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	return this.ontSdk.SendTransaction(tx)
}

func (this *OntId) NewRegIDWithSingleControllerTransaction(gasPrice, gasLimit uint64, ontId string, controller string,
	index uint32, proof []byte) (*types.MutableTransaction, error) {
	type regIDWithSingleController struct {
		OntId      string
		Controller []byte
		Index      uint32
		Proof      []byte
	}
	return this.native.NewNativeInvokeTransaction(
		gasPrice,
		gasLimit,
		ONT_ID_CONTRACT_VERSION,
		ONT_ID_CONTRACT_ADDRESS,
		"regIDWithController",
		[]interface{}{
			&regIDWithSingleController{
				OntId:      ontId,
				Controller: []byte(controller),
				Index:      index,
				Proof:      proof,
			},
		},
	)
}

func (this *OntId) RegIDWithSingleController(gasPrice, gasLimit uint64, payer *Account, signer *Account, ontId string,
	controller string, index uint32, proof []byte, controllerSigner *Account) (common.Uint256, error) {
	tx, err := this.NewRegIDWithSingleControllerTransaction(gasPrice, gasLimit, ontId, controller, index, proof)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	if payer != nil {
		this.ontSdk.SetPayer(tx, payer.Address)
		err = this.ontSdk.SignToTransaction(tx, payer)
		if err != nil {
			return common.UINT256_EMPTY, err
		}
	}
	err = this.ontSdk.SignToTransaction(tx, signer)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	err = this.ontSdk.SignToTransaction(tx, controllerSigner)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	return this.ontSdk.SendTransaction(tx)
}

func (this *OntId) NewRegIDWithMultiControllerTransaction(gasPrice, gasLimit uint64, ontId string, controller *ontid.Group,
	proof []byte) (*types.MutableTransaction, error) {
	c := controller.Serialize()
	type regIDWithMultiController struct {
		OntId      string
		Controller []byte
		Proof      []byte
	}
	return this.native.NewNativeInvokeTransaction(
		gasPrice,
		gasLimit,
		ONT_ID_CONTRACT_VERSION,
		ONT_ID_CONTRACT_ADDRESS,
		"regIDWithController",
		[]interface{}{
			&regIDWithMultiController{
				OntId:      ontId,
				Controller: c,
				Proof:      proof,
			},
		},
	)
}

func (this *OntId) RegIDWithMultiController(gasPrice, gasLimit uint64, payer *Account, signer *Account, ontId string,
	controller *ontid.Group, proof []byte, controllerSigners []*Account) (common.Uint256, error) {
	tx, err := this.NewRegIDWithMultiControllerTransaction(gasPrice, gasLimit, ontId, controller, proof)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	if payer != nil {
		this.ontSdk.SetPayer(tx, payer.Address)
		err = this.ontSdk.SignToTransaction(tx, payer)
		if err != nil {
			return common.UINT256_EMPTY, err
		}
	}
	err = this.ontSdk.SignToTransaction(tx, signer)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	for _, s := range controllerSigners {
		err = this.ontSdk.SignToTransaction(tx, s)
		if err != nil {
			return common.UINT256_EMPTY, err
		}
	}
	return this.ontSdk.SendTransaction(tx)
}

func (this *OntId) NewRevokeIDTransaction(gasPrice, gasLimit uint64, ontId string, index uint32) (*types.MutableTransaction, error) {
	type revokeID struct {
		OntId string
		Index uint32
	}
	return this.native.NewNativeInvokeTransaction(
		gasPrice,
		gasLimit,
		ONT_ID_CONTRACT_VERSION,
		ONT_ID_CONTRACT_ADDRESS,
		"revokeID",
		[]interface{}{
			&revokeID{
				OntId: ontId,
				Index: index,
			},
		},
	)
}

func (this *OntId) RevokeID(gasPrice, gasLimit uint64, payer *Account, signer *Account, ontId string,
	index uint32, pk *Account) (common.Uint256, error) {
	tx, err := this.NewRevokeIDTransaction(gasPrice, gasLimit, ontId, index)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	if payer != nil {
		this.ontSdk.SetPayer(tx, payer.Address)
		err = this.ontSdk.SignToTransaction(tx, payer)
		if err != nil {
			return common.UINT256_EMPTY, err
		}
	}
	err = this.ontSdk.SignToTransaction(tx, signer)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	err = this.ontSdk.SignToTransaction(tx, pk)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	return this.ontSdk.SendTransaction(tx)
}

func (this *OntId) NewRevokeIDBySingleControllerTransaction(gasPrice, gasLimit uint64, ontId string, index uint32) (*types.MutableTransaction, error) {
	type revokeIDBySingleController struct {
		OntId string
		Index uint32
	}
	return this.native.NewNativeInvokeTransaction(
		gasPrice,
		gasLimit,
		ONT_ID_CONTRACT_VERSION,
		ONT_ID_CONTRACT_ADDRESS,
		"revokeIDByController",
		[]interface{}{
			&revokeIDBySingleController{
				OntId: ontId,
				Index: index,
			},
		},
	)
}

func (this *OntId) RevokeIDBySingleController(gasPrice, gasLimit uint64, payer *Account, signer *Account, ontId string,
	index uint32, controllerSigner *Account) (common.Uint256, error) {
	tx, err := this.NewRevokeIDBySingleControllerTransaction(gasPrice, gasLimit, ontId, index)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	if payer != nil {
		this.ontSdk.SetPayer(tx, payer.Address)
		err = this.ontSdk.SignToTransaction(tx, payer)
		if err != nil {
			return common.UINT256_EMPTY, err
		}
	}
	err = this.ontSdk.SignToTransaction(tx, signer)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	err = this.ontSdk.SignToTransaction(tx, controllerSigner)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	return this.ontSdk.SendTransaction(tx)
}

func (this *OntId) NewRevokeIDByMultiControllerTransaction(gasPrice, gasLimit uint64, ontId string, signers []ontid.Signer) (*types.MutableTransaction, error) {
	s := ontid.SerializeSigners(signers)
	type revokeIDByMultiController struct {
		OntId string
		S     []byte
	}
	return this.native.NewNativeInvokeTransaction(
		gasPrice,
		gasLimit,
		ONT_ID_CONTRACT_VERSION,
		ONT_ID_CONTRACT_ADDRESS,
		"revokeIDByController",
		[]interface{}{
			&revokeIDByMultiController{
				OntId: ontId,
				S:     s,
			},
		},
	)
}

func (this *OntId) RevokeIDByMultiController(gasPrice, gasLimit uint64, payer *Account, signer *Account, ontId string,
	signers []ontid.Signer, controllerSigners []*Account) (common.Uint256, error) {
	tx, err := this.NewRevokeIDByMultiControllerTransaction(gasPrice, gasLimit, ontId, signers)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	if payer != nil {
		this.ontSdk.SetPayer(tx, payer.Address)
		err = this.ontSdk.SignToTransaction(tx, payer)
		if err != nil {
			return common.UINT256_EMPTY, err
		}
	}
	err = this.ontSdk.SignToTransaction(tx, signer)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	for _, s := range controllerSigners {
		err = this.ontSdk.SignToTransaction(tx, s)
		if err != nil {
			return common.UINT256_EMPTY, err
		}
	}
	return this.ontSdk.SendTransaction(tx)
}

func (this *OntId) NewRemoveControllerTransaction(gasPrice, gasLimit uint64, ontId string,
	index uint32, proof []byte) (*types.MutableTransaction, error) {
	type removeController struct {
		OntId string
		Index uint32
		Proof []byte
	}
	return this.native.NewNativeInvokeTransaction(
		gasPrice,
		gasLimit,
		ONT_ID_CONTRACT_VERSION,
		ONT_ID_CONTRACT_ADDRESS,
		"removeController",
		[]interface{}{
			&removeController{
				OntId: ontId,
				Index: index,
				Proof: proof,
			},
		},
	)
}

func (this *OntId) RemoveController(gasPrice, gasLimit uint64, payer *Account, signer *Account, ontId string,
	index uint32, proof []byte, pk *Account) (common.Uint256, error) {
	tx, err := this.NewRemoveControllerTransaction(gasPrice, gasLimit, ontId, index, proof)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	if payer != nil {
		this.ontSdk.SetPayer(tx, payer.Address)
		err = this.ontSdk.SignToTransaction(tx, payer)
		if err != nil {
			return common.UINT256_EMPTY, err
		}
	}
	err = this.ontSdk.SignToTransaction(tx, signer)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	err = this.ontSdk.SignToTransaction(tx, pk)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	return this.ontSdk.SendTransaction(tx)
}

func (this *OntId) NewRegIDWithAttributesTransaction(gasPrice, gasLimit uint64, ontId string, pubKey keypair.PublicKey,
	attributes []*DDOAttribute, access string, proof []byte) (*types.MutableTransaction, error) {
	type regIDWithAttribute struct {
		OntId      string
		PubKey     []byte
		Attributes []*DDOAttribute
		Access     string
		Proof      []byte
	}
	return this.native.NewNativeInvokeTransaction(
		gasPrice,
		gasLimit,
		ONT_ID_CONTRACT_VERSION,
		ONT_ID_CONTRACT_ADDRESS,
		"regIDWithAttributes",
		[]interface{}{
			&regIDWithAttribute{
				OntId:      ontId,
				PubKey:     keypair.SerializePublicKey(pubKey),
				Attributes: attributes,
				Access:     access,
				Proof:      proof,
			},
		},
	)
}

func (this *OntId) RegIDWithAttributes(gasPrice, gasLimit uint64, payer, signer *Account, ontId string,
	attributes []*DDOAttribute, access string, proof []byte, pk *Account) (common.Uint256, error) {
	tx, err := this.NewRegIDWithAttributesTransaction(gasPrice, gasLimit, ontId, pk.PublicKey, attributes, access, proof)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	if payer != nil {
		this.ontSdk.SetPayer(tx, payer.Address)
		err = this.ontSdk.SignToTransaction(tx, payer)
		if err != nil {
			return common.UINT256_EMPTY, err
		}
	}
	err = this.ontSdk.SignToTransaction(tx, signer)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	err = this.ontSdk.SignToTransaction(tx, pk)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	return this.ontSdk.SendTransaction(tx)
}

func (this *OntId) NewAddKeyTransaction(gasPrice, gasLimit uint64, ontId string, newPubKey []byte, pubKey keypair.PublicKey,
	controller, access string, proof []byte) (*types.MutableTransaction, error) {
	type addKey struct {
		OntId      string
		NewPubKey  []byte
		PubKey     []byte
		Controller []byte
		Access     string
		Proof      []byte
	}
	return this.native.NewNativeInvokeTransaction(
		gasPrice,
		gasLimit,
		ONT_ID_CONTRACT_VERSION,
		ONT_ID_CONTRACT_ADDRESS,
		"addKey",
		[]interface{}{
			&addKey{
				OntId:      ontId,
				NewPubKey:  newPubKey,
				PubKey:     keypair.SerializePublicKey(pubKey),
				Controller: []byte(controller),
				Access:     access,
				Proof:      proof,
			},
		})
}

func (this *OntId) AddKey(gasPrice, gasLimit uint64, payer *Account, ontId string, signer *Account,
	newPubKey []byte, controller, access string, proof []byte, pk *Account) (common.Uint256, error) {
	tx, err := this.NewAddKeyTransaction(gasPrice, gasLimit, ontId, newPubKey, pk.PublicKey, controller, access, proof)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	if payer != nil {
		this.ontSdk.SetPayer(tx, payer.Address)
		err = this.ontSdk.SignToTransaction(tx, payer)
		if err != nil {
			return common.UINT256_EMPTY, err
		}
	}
	err = this.ontSdk.SignToTransaction(tx, signer)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	err = this.ontSdk.SignToTransaction(tx, pk)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	return this.ontSdk.SendTransaction(tx)
}

func (this *OntId) NewRevokeKeyTransaction(gasPrice, gasLimit uint64, ontId string, removedPubKey []byte,
	pubKey keypair.PublicKey, proof []byte) (*types.MutableTransaction, error) {
	type removeKey struct {
		OntId      string
		RemovedKey []byte
		PubKey     []byte
		Proof      []byte
	}
	return this.native.NewNativeInvokeTransaction(
		gasPrice,
		gasLimit,
		ONT_ID_CONTRACT_VERSION,
		ONT_ID_CONTRACT_ADDRESS,
		"removeKey",
		[]interface{}{
			&removeKey{
				OntId:      ontId,
				RemovedKey: removedPubKey,
				PubKey:     keypair.SerializePublicKey(pubKey),
				Proof:      proof,
			},
		},
	)
}

func (this *OntId) RevokeKey(gasPrice, gasLimit uint64, payer *Account, ontId string, signer *Account,
	removedPubKey []byte, proof []byte, pk *Account) (common.Uint256, error) {
	tx, err := this.NewRevokeKeyTransaction(gasPrice, gasLimit, ontId, removedPubKey, pk.PublicKey, proof)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	if payer != nil {
		this.ontSdk.SetPayer(tx, payer.Address)
		err = this.ontSdk.SignToTransaction(tx, payer)
		if err != nil {
			return common.UINT256_EMPTY, err
		}
	}
	err = this.ontSdk.SignToTransaction(tx, signer)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	err = this.ontSdk.SignToTransaction(tx, pk)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	return this.ontSdk.SendTransaction(tx)
}

func (this *OntId) NewSetRecoveryTransaction(gasPrice, gasLimit uint64, ontId string, recovery *ontid.Group,
	index uint32, proof []byte) (*types.MutableTransaction, error) {
	r := recovery.Serialize()
	type setRecovery struct {
		OntId    string
		Recovery []byte
		Index    uint32
		Proof    []byte
	}
	return this.native.NewNativeInvokeTransaction(
		gasPrice,
		gasLimit,
		ONT_ID_CONTRACT_VERSION,
		ONT_ID_CONTRACT_ADDRESS,
		"setRecovery",
		[]interface{}{
			&setRecovery{
				OntId:    ontId,
				Recovery: r,
				Index:    index,
				Proof:    proof,
			},
		})
}

func (this *OntId) SetRecovery(gasPrice, gasLimit uint64, payer, signer *Account, ontId string, recovery *ontid.Group,
	index uint32, proof []byte, pk *Account) (common.Uint256, error) {
	tx, err := this.NewSetRecoveryTransaction(gasPrice, gasLimit, ontId, recovery, index, proof)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	if payer != nil {
		this.ontSdk.SetPayer(tx, payer.Address)
		err = this.ontSdk.SignToTransaction(tx, payer)
		if err != nil {
			return common.UINT256_EMPTY, err
		}
	}
	err = this.ontSdk.SignToTransaction(tx, signer)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	err = this.ontSdk.SignToTransaction(tx, pk)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	return this.ontSdk.SendTransaction(tx)
}

func (this *OntId) NewUpdateRecoveryTransaction(gasPrice, gasLimit uint64, ontId string,
	newRecovery *ontid.Group, signers []ontid.Signer, proof []byte) (*types.MutableTransaction, error) {
	r := newRecovery.Serialize()
	s := ontid.SerializeSigners(signers)
	type updateRecovery struct {
		OntId string
		R     []byte
		S     []byte
		Proof []byte
	}
	return this.native.NewNativeInvokeTransaction(
		gasPrice,
		gasLimit,
		ONT_ID_CONTRACT_VERSION,
		ONT_ID_CONTRACT_ADDRESS,
		"updateRecovery",
		[]interface{}{
			&updateRecovery{
				OntId: ontId,
				R:     r,
				S:     s,
				Proof: proof,
			},
		},
	)
}

func (this *OntId) UpdateRecovery(gasPrice, gasLimit uint64, payer *Account, signer *Account, ontId string,
	newRecovery *ontid.Group, signers []ontid.Signer, proof []byte, recoverySigners []*Account) (common.Uint256, error) {
	tx, err := this.NewUpdateRecoveryTransaction(gasPrice, gasLimit, ontId, newRecovery, signers, proof)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	if payer != nil {
		this.ontSdk.SetPayer(tx, payer.Address)
		err = this.ontSdk.SignToTransaction(tx, payer)
		if err != nil {
			return common.UINT256_EMPTY, err
		}
	}
	err = this.ontSdk.SignToTransaction(tx, signer)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	for _, s := range recoverySigners {
		err = this.ontSdk.SignToTransaction(tx, s)
		if err != nil {
			return common.UINT256_EMPTY, err
		}
	}
	return this.ontSdk.SendTransaction(tx)
}

func (this *OntId) NewAddKeyBySingleControllerTransaction(gasPrice, gasLimit uint64, ontId string, publicKey []byte,
	index uint32, controller, access string, proof []byte) (*types.MutableTransaction, error) {
	type addKeyBySingleController struct {
		OntId      string
		PublicKey  []byte
		Index      uint32
		Controller []byte
		Access     string
		Proof      []byte
	}
	return this.native.NewNativeInvokeTransaction(
		gasPrice,
		gasLimit,
		ONT_ID_CONTRACT_VERSION,
		ONT_ID_CONTRACT_ADDRESS,
		"addKeyByController",
		[]interface{}{
			&addKeyBySingleController{
				OntId:      ontId,
				PublicKey:  publicKey,
				Index:      index,
				Controller: []byte(controller),
				Access:     access,
				Proof:      proof,
			},
		},
	)
}

func (this *OntId) AddKeyBySingleController(gasPrice, gasLimit uint64, payer *Account, signer *Account, ontId string,
	publicKey []byte, index uint32, controller, access string, proof []byte, controllerSigner *Account) (common.Uint256, error) {
	tx, err := this.NewAddKeyBySingleControllerTransaction(gasPrice, gasLimit, ontId, publicKey, index, controller, access, proof)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	if payer != nil {
		this.ontSdk.SetPayer(tx, payer.Address)
		err = this.ontSdk.SignToTransaction(tx, payer)
		if err != nil {
			return common.UINT256_EMPTY, err
		}
	}
	err = this.ontSdk.SignToTransaction(tx, signer)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	err = this.ontSdk.SignToTransaction(tx, controllerSigner)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	return this.ontSdk.SendTransaction(tx)
}

func (this *OntId) NewAddKeyByMultiControllerTransaction(gasPrice, gasLimit uint64, ontId string, publicKey []byte,
	signers []ontid.Signer, controller, access string, proof []byte) (*types.MutableTransaction, error) {
	s := ontid.SerializeSigners(signers)
	type addKeyByMultiController struct {
		OntId      string
		PublicKey  []byte
		Signers    []byte
		Controller []byte
		Access     string
		Proof      []byte
	}
	return this.native.NewNativeInvokeTransaction(
		gasPrice,
		gasLimit,
		ONT_ID_CONTRACT_VERSION,
		ONT_ID_CONTRACT_ADDRESS,
		"addKeyByController",
		[]interface{}{
			&addKeyByMultiController{
				OntId:      ontId,
				PublicKey:  publicKey,
				Signers:    s,
				Controller: []byte(controller),
				Access:     access,
				Proof:      proof,
			},
		},
	)
}

func (this *OntId) AddKeyByMultiController(gasPrice, gasLimit uint64, payer *Account, signer *Account, ontId string,
	publicKey []byte, signers []ontid.Signer, controller, access string, proof []byte, controllerSigners []*Account) (common.Uint256, error) {
	tx, err := this.NewAddKeyByMultiControllerTransaction(gasPrice, gasLimit, ontId, publicKey, signers, controller, access, proof)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	if payer != nil {
		this.ontSdk.SetPayer(tx, payer.Address)
		err = this.ontSdk.SignToTransaction(tx, payer)
		if err != nil {
			return common.UINT256_EMPTY, err
		}
	}
	err = this.ontSdk.SignToTransaction(tx, signer)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	for _, s := range controllerSigners {
		err = this.ontSdk.SignToTransaction(tx, s)
		if err != nil {
			return common.UINT256_EMPTY, err
		}
	}
	return this.ontSdk.SendTransaction(tx)
}

func (this *OntId) NewRemoveKeyBySingleControllerTransaction(gasPrice, gasLimit uint64, ontId string, publicKeyIndex uint32,
	controllerIndex uint32, proof []byte) (*types.MutableTransaction, error) {
	type removeKeyBySingleController struct {
		OntId           string
		PublicKeyIndex  uint32
		ControllerIndex uint32
		Proof           []byte
	}
	return this.native.NewNativeInvokeTransaction(
		gasPrice,
		gasLimit,
		ONT_ID_CONTRACT_VERSION,
		ONT_ID_CONTRACT_ADDRESS,
		"removeKeyByController",
		[]interface{}{
			&removeKeyBySingleController{
				OntId:           ontId,
				PublicKeyIndex:  publicKeyIndex,
				ControllerIndex: controllerIndex,
				Proof:           proof,
			},
		},
	)
}

func (this *OntId) RemoveKeyBySingleController(gasPrice, gasLimit uint64, payer *Account, signer *Account, ontId string,
	publicKeyIndex uint32, controllerIndex uint32, proof []byte, controllerSigner *Account) (common.Uint256, error) {
	tx, err := this.NewRemoveKeyBySingleControllerTransaction(gasPrice, gasLimit, ontId, publicKeyIndex, controllerIndex, proof)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	if payer != nil {
		this.ontSdk.SetPayer(tx, payer.Address)
		err = this.ontSdk.SignToTransaction(tx, payer)
		if err != nil {
			return common.UINT256_EMPTY, err
		}
	}
	err = this.ontSdk.SignToTransaction(tx, signer)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	err = this.ontSdk.SignToTransaction(tx, controllerSigner)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	return this.ontSdk.SendTransaction(tx)
}

func (this *OntId) NewRemoveKeyByMultiControllerTransaction(gasPrice, gasLimit uint64, ontId string, publicKeyIndex []byte,
	signers []ontid.Signer, proof []byte) (*types.MutableTransaction, error) {
	s := ontid.SerializeSigners(signers)
	type removeKeyByMultiController struct {
		OntId          string
		publicKeyIndex []byte
		Signers        []byte
		Proof          []byte
	}
	return this.native.NewNativeInvokeTransaction(
		gasPrice,
		gasLimit,
		ONT_ID_CONTRACT_VERSION,
		ONT_ID_CONTRACT_ADDRESS,
		"removeKeyByController",
		[]interface{}{
			&removeKeyByMultiController{
				OntId:          ontId,
				publicKeyIndex: publicKeyIndex,
				Signers:        s,
				Proof:          proof,
			},
		},
	)
}

func (this *OntId) RemoveKeyByMultiController(gasPrice, gasLimit uint64, payer *Account, signer *Account, ontId string,
	publicKeyIndex []byte, signers []ontid.Signer, proof []byte, controllerSigners []*Account) (common.Uint256, error) {
	tx, err := this.NewRemoveKeyByMultiControllerTransaction(gasPrice, gasLimit, ontId, publicKeyIndex, signers, proof)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	if payer != nil {
		this.ontSdk.SetPayer(tx, payer.Address)
		err = this.ontSdk.SignToTransaction(tx, payer)
		if err != nil {
			return common.UINT256_EMPTY, err
		}
	}
	err = this.ontSdk.SignToTransaction(tx, signer)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	for _, s := range controllerSigners {
		err = this.ontSdk.SignToTransaction(tx, s)
		if err != nil {
			return common.UINT256_EMPTY, err
		}
	}
	return this.ontSdk.SendTransaction(tx)
}

func (this *OntId) NewAddKeyByRecoveryTransaction(gasPrice, gasLimit uint64, ontId string,
	publicKey []byte, signers []ontid.Signer, proof []byte) (*types.MutableTransaction, error) {
	s := ontid.SerializeSigners(signers)
	type addKeyByRecovery struct {
		OntId     string
		PublicKey []byte
		S         []byte
		Proof     []byte
	}
	return this.native.NewNativeInvokeTransaction(
		gasPrice,
		gasLimit,
		ONT_ID_CONTRACT_VERSION,
		ONT_ID_CONTRACT_ADDRESS,
		"addKeyByRecovery",
		[]interface{}{
			&addKeyByRecovery{
				OntId:     ontId,
				PublicKey: publicKey,
				S:         s,
				Proof:     proof,
			},
		},
	)
}

func (this *OntId) AddKeyByRecovery(gasPrice, gasLimit uint64, payer *Account, signer *Account, ontId string,
	publicKey []byte, signers []ontid.Signer, proof []byte, recoverySigners []*Account) (common.Uint256, error) {
	tx, err := this.NewAddKeyByRecoveryTransaction(gasPrice, gasLimit, ontId, publicKey, signers, proof)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	if payer != nil {
		this.ontSdk.SetPayer(tx, payer.Address)
		err = this.ontSdk.SignToTransaction(tx, payer)
		if err != nil {
			return common.UINT256_EMPTY, err
		}
	}
	err = this.ontSdk.SignToTransaction(tx, signer)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	for _, s := range recoverySigners {
		err = this.ontSdk.SignToTransaction(tx, s)
		if err != nil {
			return common.UINT256_EMPTY, err
		}
	}
	return this.ontSdk.SendTransaction(tx)
}

func (this *OntId) NewRemoveKeyByRecoveryTransaction(gasPrice, gasLimit uint64, ontId string,
	publicKeyIndex uint32, signers []ontid.Signer, proof []byte) (*types.MutableTransaction, error) {
	s := ontid.SerializeSigners(signers)
	type removeKeyByRecovery struct {
		OntId          string
		PublicKeyIndex uint32
		S              []byte
		Proof          []byte
	}
	return this.native.NewNativeInvokeTransaction(
		gasPrice,
		gasLimit,
		ONT_ID_CONTRACT_VERSION,
		ONT_ID_CONTRACT_ADDRESS,
		"removeKeyByRecovery",
		[]interface{}{
			&removeKeyByRecovery{
				OntId:          ontId,
				PublicKeyIndex: publicKeyIndex,
				S:              s,
				Proof:          proof,
			},
		},
	)
}

func (this *OntId) RemoveKeyByRecovery(gasPrice, gasLimit uint64, payer *Account, signer *Account, ontId string,
	publicKeyIndex uint32, signers []ontid.Signer, proof []byte, recoverySigners []*Account) (common.Uint256, error) {
	tx, err := this.NewRemoveKeyByRecoveryTransaction(gasPrice, gasLimit, ontId, publicKeyIndex, signers, proof)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	if payer != nil {
		this.ontSdk.SetPayer(tx, payer.Address)
		err = this.ontSdk.SignToTransaction(tx, payer)
		if err != nil {
			return common.UINT256_EMPTY, err
		}
	}
	err = this.ontSdk.SignToTransaction(tx, signer)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	for _, s := range recoverySigners {
		err = this.ontSdk.SignToTransaction(tx, s)
		if err != nil {
			return common.UINT256_EMPTY, err
		}
	}
	return this.ontSdk.SendTransaction(tx)
}

func (this *OntId) NewAddAttributesTransaction(gasPrice, gasLimit uint64, ontId string, attributes []*DDOAttribute,
	pubKey keypair.PublicKey, proof []byte) (*types.MutableTransaction, error) {
	type addAttributes struct {
		OntId      string
		Attributes []*DDOAttribute
		PubKey     []byte
		Proof      []byte
	}
	return this.native.NewNativeInvokeTransaction(
		gasPrice,
		gasLimit,
		ONT_ID_CONTRACT_VERSION,
		ONT_ID_CONTRACT_ADDRESS,
		"addAttributes",
		[]interface{}{
			&addAttributes{
				OntId:      ontId,
				Attributes: attributes,
				PubKey:     keypair.SerializePublicKey(pubKey),
				Proof:      proof,
			},
		})
}

func (this *OntId) AddAttributes(gasPrice, gasLimit uint64, payer, signer *Account, ontId string,
	attributes []*DDOAttribute, proof []byte, pk *Account) (common.Uint256, error) {
	tx, err := this.NewAddAttributesTransaction(gasPrice, gasLimit, ontId, attributes, pk.PublicKey, proof)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	if payer != nil {
		this.ontSdk.SetPayer(tx, payer.Address)
		err = this.ontSdk.SignToTransaction(tx, payer)
		if err != nil {
			return common.UINT256_EMPTY, err
		}
	}
	err = this.ontSdk.SignToTransaction(tx, signer)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	err = this.ontSdk.SignToTransaction(tx, pk)
	if err != nil {
		return common.UINT256_EMPTY, err
	}

	return this.ontSdk.SendTransaction(tx)
}

func (this *OntId) NewRemoveAttributeTransaction(gasPrice, gasLimit uint64, ontId string, key []byte, pubKey keypair.PublicKey) (*types.MutableTransaction, error) {
	type removeAttribute struct {
		OntId  string
		Key    []byte
		PubKey []byte
	}
	return this.native.NewNativeInvokeTransaction(
		gasPrice,
		gasLimit,
		ONT_ID_CONTRACT_VERSION,
		ONT_ID_CONTRACT_ADDRESS,
		"removeAttribute",
		[]interface{}{
			&removeAttribute{
				OntId:  ontId,
				Key:    key,
				PubKey: keypair.SerializePublicKey(pubKey),
			},
		})
}

func (this *OntId) RemoveAttribute(gasPrice, gasLimit uint64, payer, signer *Account, ontId string, removeKey []byte,
	pk *Account) (common.Uint256, error) {
	tx, err := this.NewRemoveAttributeTransaction(gasPrice, gasLimit, ontId, removeKey, pk.PublicKey)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	if payer != nil {
		this.ontSdk.SetPayer(tx, payer.Address)
		err = this.ontSdk.SignToTransaction(tx, payer)
		if err != nil {
			return common.UINT256_EMPTY, err
		}
	}
	err = this.ontSdk.SignToTransaction(tx, signer)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	err = this.ontSdk.SignToTransaction(tx, pk)
	if err != nil {
		return common.UINT256_EMPTY, err
	}

	return this.ontSdk.SendTransaction(tx)
}

func (this *OntId) NewAddAttributesBySingleControllerTransaction(gasPrice, gasLimit uint64, ontId string, attributes []*DDOAttribute,
	index uint32, proof []byte) (*types.MutableTransaction, error) {
	type addAttributesBySingleController struct {
		OntId      string
		Attributes []*DDOAttribute
		Index      uint32
		Proof      []byte
	}
	return this.native.NewNativeInvokeTransaction(
		gasPrice,
		gasLimit,
		ONT_ID_CONTRACT_VERSION,
		ONT_ID_CONTRACT_ADDRESS,
		"addAttributesByController",
		[]interface{}{
			&addAttributesBySingleController{
				OntId:      ontId,
				Attributes: attributes,
				Index:      index,
				Proof:      proof,
			},
		},
	)
}

func (this *OntId) AddAttributesBySingleController(gasPrice, gasLimit uint64, payer *Account, signer *Account, ontId string,
	attributes []*DDOAttribute, index uint32, proof []byte, controllerSigner *Account) (common.Uint256, error) {
	tx, err := this.NewAddAttributesBySingleControllerTransaction(gasPrice, gasLimit, ontId, attributes, index, proof)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	if payer != nil {
		this.ontSdk.SetPayer(tx, payer.Address)
		err = this.ontSdk.SignToTransaction(tx, payer)
		if err != nil {
			return common.UINT256_EMPTY, err
		}
	}
	err = this.ontSdk.SignToTransaction(tx, signer)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	err = this.ontSdk.SignToTransaction(tx, controllerSigner)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	return this.ontSdk.SendTransaction(tx)
}

func (this *OntId) NewAddAttributesByMultiControllerTransaction(gasPrice, gasLimit uint64, ontId string, attributes []*DDOAttribute,
	signers []ontid.Signer, proof []byte) (*types.MutableTransaction, error) {
	s := ontid.SerializeSigners(signers)
	type addAttributesByMultiController struct {
		OntId      string
		Attributes []*DDOAttribute
		Signers    []byte
		Proof      []byte
	}
	return this.native.NewNativeInvokeTransaction(
		gasPrice,
		gasLimit,
		ONT_ID_CONTRACT_VERSION,
		ONT_ID_CONTRACT_ADDRESS,
		"addAttributesByController",
		[]interface{}{
			&addAttributesByMultiController{
				OntId:      ontId,
				Attributes: attributes,
				Signers:    s,
				Proof:      proof,
			},
		},
	)
}

func (this *OntId) AddAttributesByMultiController(gasPrice, gasLimit uint64, payer *Account, signer *Account, ontId string,
	attributes []*DDOAttribute, signers []ontid.Signer, proof []byte, controllerSigners []*Account) (common.Uint256, error) {
	tx, err := this.NewAddAttributesByMultiControllerTransaction(gasPrice, gasLimit, ontId, attributes, signers, proof)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	if payer != nil {
		this.ontSdk.SetPayer(tx, payer.Address)
		err = this.ontSdk.SignToTransaction(tx, payer)
		if err != nil {
			return common.UINT256_EMPTY, err
		}
	}
	err = this.ontSdk.SignToTransaction(tx, signer)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	for _, s := range controllerSigners {
		err = this.ontSdk.SignToTransaction(tx, s)
		if err != nil {
			return common.UINT256_EMPTY, err
		}
	}
	return this.ontSdk.SendTransaction(tx)
}

func (this *OntId) NewRemoveAttributesBySingleControllerTransaction(gasPrice, gasLimit uint64, ontId string, key []byte,
	index uint32, proof []byte) (*types.MutableTransaction, error) {
	type removeAttributesBySingleController struct {
		OntId string
		Key   []byte
		Index uint32
		Proof []byte
	}
	return this.native.NewNativeInvokeTransaction(
		gasPrice,
		gasLimit,
		ONT_ID_CONTRACT_VERSION,
		ONT_ID_CONTRACT_ADDRESS,
		"removeAttributesByController",
		[]interface{}{
			&removeAttributesBySingleController{
				OntId: ontId,
				Key:   key,
				Index: index,
				Proof: proof,
			},
		},
	)
}

func (this *OntId) RemoveAttributesBySingleController(gasPrice, gasLimit uint64, payer *Account, signer *Account, ontId string,
	key []byte, index uint32, proof []byte, controllerSigner *Account) (common.Uint256, error) {
	tx, err := this.NewRemoveAttributesBySingleControllerTransaction(gasPrice, gasLimit, ontId, key, index, proof)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	if payer != nil {
		this.ontSdk.SetPayer(tx, payer.Address)
		err = this.ontSdk.SignToTransaction(tx, payer)
		if err != nil {
			return common.UINT256_EMPTY, err
		}
	}
	err = this.ontSdk.SignToTransaction(tx, signer)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	err = this.ontSdk.SignToTransaction(tx, controllerSigner)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	return this.ontSdk.SendTransaction(tx)
}

func (this *OntId) NewRemoveAttributesByMultiControllerTransaction(gasPrice, gasLimit uint64, ontId string, key []byte,
	signers []ontid.Signer, proof []byte) (*types.MutableTransaction, error) {
	s := ontid.SerializeSigners(signers)
	type removeAttributesByMultiController struct {
		OntId   string
		Key     []byte
		Signers []byte
		Proof   []byte
	}
	return this.native.NewNativeInvokeTransaction(
		gasPrice,
		gasLimit,
		ONT_ID_CONTRACT_VERSION,
		ONT_ID_CONTRACT_ADDRESS,
		"removeAttributesByController",
		[]interface{}{
			&removeAttributesByMultiController{
				OntId:   ontId,
				Key:     key,
				Signers: s,
				Proof:   proof,
			},
		},
	)
}

func (this *OntId) RemoveAttributesByMultiController(gasPrice, gasLimit uint64, payer *Account, signer *Account, ontId string,
	key []byte, signers []ontid.Signer, proof []byte, controllerSigners []*Account) (common.Uint256, error) {
	tx, err := this.NewRemoveAttributesByMultiControllerTransaction(gasPrice, gasLimit, ontId, key, signers, proof)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	if payer != nil {
		this.ontSdk.SetPayer(tx, payer.Address)
		err = this.ontSdk.SignToTransaction(tx, payer)
		if err != nil {
			return common.UINT256_EMPTY, err
		}
	}
	err = this.ontSdk.SignToTransaction(tx, signer)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	for _, s := range controllerSigners {
		err = this.ontSdk.SignToTransaction(tx, s)
		if err != nil {
			return common.UINT256_EMPTY, err
		}
	}
	return this.ontSdk.SendTransaction(tx)
}

func (this *OntId) NewAddAuthKeyTransaction(gasPrice, gasLimit uint64, ontId string, ifNewPublicKey bool, index uint32,
	publicKey []byte, controller string, signIndex uint32, proof []byte) (*types.MutableTransaction, error) {
	type NewPublicKey struct {
		Key        []byte
		Controller []byte
	}
	type AddAuthKeyParam struct {
		OntId          []byte
		IfNewPublicKey bool
		Index          uint32
		NewPublicKey   *NewPublicKey
		SignIndex      uint32
		Proof          []byte
	}

	return this.native.NewNativeInvokeTransaction(
		gasPrice,
		gasLimit,
		ONT_ID_CONTRACT_VERSION,
		ONT_ID_CONTRACT_ADDRESS,
		"addAuthKey",
		[]interface{}{
			&AddAuthKeyParam{
				OntId:          []byte(ontId),
				IfNewPublicKey: ifNewPublicKey,
				Index:          index,
				NewPublicKey: &NewPublicKey{
					Key:        publicKey,
					Controller: []byte(controller),
				},
				SignIndex: signIndex,
				Proof:     proof,
			},
		})
}

func (this *OntId) AddAuthKey(gasPrice, gasLimit uint64, payer, signer *Account, ontId string, ifNewPublicKey bool,
	index uint32, publicKey []byte, controller string, signIndex uint32, proof []byte, pk *Account) (common.Uint256, error) {
	tx, err := this.NewAddAuthKeyTransaction(gasPrice, gasLimit, ontId, ifNewPublicKey, index, publicKey, controller, signIndex, proof)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	if payer != nil {
		this.ontSdk.SetPayer(tx, payer.Address)
		err = this.ontSdk.SignToTransaction(tx, payer)
		if err != nil {
			return common.UINT256_EMPTY, err
		}
	}
	err = this.ontSdk.SignToTransaction(tx, signer)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	err = this.ontSdk.SignToTransaction(tx, pk)
	if err != nil {
		return common.UINT256_EMPTY, err
	}

	return this.ontSdk.SendTransaction(tx)
}

func (this *OntId) NewRemoveAuthKeyTransaction(gasPrice, gasLimit uint64, ontId string, index uint32,
	signIndex uint32, proof []byte) (*types.MutableTransaction, error) {
	type RemoveAuthKeyParam struct {
		OntId     []byte
		Index     uint32
		SignIndex uint32
		Proof     []byte
	}

	return this.native.NewNativeInvokeTransaction(
		gasPrice,
		gasLimit,
		ONT_ID_CONTRACT_VERSION,
		ONT_ID_CONTRACT_ADDRESS,
		"removeAuthKey",
		[]interface{}{
			&RemoveAuthKeyParam{
				OntId:     []byte(ontId),
				Index:     index,
				SignIndex: signIndex,
				Proof:     proof,
			},
		})
}

func (this *OntId) RemoveAuthKey(gasPrice, gasLimit uint64, payer, signer *Account, ontId string, index uint32,
	signIndex uint32, proof []byte, pk *Account) (common.Uint256, error) {
	tx, err := this.NewRemoveAuthKeyTransaction(gasPrice, gasLimit, ontId, index, signIndex, proof)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	if payer != nil {
		this.ontSdk.SetPayer(tx, payer.Address)
		err = this.ontSdk.SignToTransaction(tx, payer)
		if err != nil {
			return common.UINT256_EMPTY, err
		}
	}
	err = this.ontSdk.SignToTransaction(tx, signer)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	err = this.ontSdk.SignToTransaction(tx, pk)
	if err != nil {
		return common.UINT256_EMPTY, err
	}

	return this.ontSdk.SendTransaction(tx)
}

func (this *OntId) NewAddServiceTransaction(gasPrice, gasLimit uint64, ontId string, serviceId, type_, serviceEndpint []byte,
	index uint32, proof []byte) (*types.MutableTransaction, error) {
	type ServiceParam struct {
		OntId          []byte
		ServiceId      []byte
		Type           []byte
		ServiceEndpint []byte
		Index          uint32
		Proof          []byte
	}

	return this.native.NewNativeInvokeTransaction(
		gasPrice,
		gasLimit,
		ONT_ID_CONTRACT_VERSION,
		ONT_ID_CONTRACT_ADDRESS,
		"addService",
		[]interface{}{
			&ServiceParam{
				OntId:          []byte(ontId),
				ServiceId:      serviceId,
				Type:           type_,
				ServiceEndpint: serviceEndpint,
				Index:          index,
				Proof:          proof,
			},
		})
}

func (this *OntId) AddService(gasPrice, gasLimit uint64, payer, signer *Account, ontId string, serviceId, type_, serviceEndpint []byte,
	index uint32, proof []byte, pk *Account) (common.Uint256, error) {
	tx, err := this.NewAddServiceTransaction(gasPrice, gasLimit, ontId, serviceId, type_, serviceEndpint, index, proof)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	if payer != nil {
		this.ontSdk.SetPayer(tx, payer.Address)
		err = this.ontSdk.SignToTransaction(tx, payer)
		if err != nil {
			return common.UINT256_EMPTY, err
		}
	}
	err = this.ontSdk.SignToTransaction(tx, signer)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	err = this.ontSdk.SignToTransaction(tx, pk)
	if err != nil {
		return common.UINT256_EMPTY, err
	}

	return this.ontSdk.SendTransaction(tx)
}

func (this *OntId) NewUpdateServiceTransaction(gasPrice, gasLimit uint64, ontId string, serviceId, type_, serviceEndpint []byte,
	index uint32, proof []byte) (*types.MutableTransaction, error) {
	type ServiceParam struct {
		OntId          []byte
		ServiceId      []byte
		Type           []byte
		ServiceEndpint []byte
		Index          uint32
		Proof          []byte
	}

	return this.native.NewNativeInvokeTransaction(
		gasPrice,
		gasLimit,
		ONT_ID_CONTRACT_VERSION,
		ONT_ID_CONTRACT_ADDRESS,
		"updateService",
		[]interface{}{
			&ServiceParam{
				OntId:          []byte(ontId),
				ServiceId:      serviceId,
				Type:           type_,
				ServiceEndpint: serviceEndpint,
				Index:          index,
				Proof:          proof,
			},
		})
}

func (this *OntId) UpdateService(gasPrice, gasLimit uint64, payer, signer *Account, ontId string, serviceId, type_, serviceEndpint []byte,
	index uint32, proof []byte, pk *Account) (common.Uint256, error) {
	tx, err := this.NewUpdateServiceTransaction(gasPrice, gasLimit, ontId, serviceId, type_, serviceEndpint, index, proof)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	if payer != nil {
		this.ontSdk.SetPayer(tx, payer.Address)
		err = this.ontSdk.SignToTransaction(tx, payer)
		if err != nil {
			return common.UINT256_EMPTY, err
		}
	}
	err = this.ontSdk.SignToTransaction(tx, signer)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	err = this.ontSdk.SignToTransaction(tx, pk)
	if err != nil {
		return common.UINT256_EMPTY, err
	}

	return this.ontSdk.SendTransaction(tx)
}

func (this *OntId) NewRemoveServiceTransaction(gasPrice, gasLimit uint64, ontId string, serviceId []byte, index uint32,
	proof []byte) (*types.MutableTransaction, error) {
	type ServiceRemoveParam struct {
		OntId     []byte
		ServiceId []byte
		Index     uint32
		Proof     []byte
	}

	return this.native.NewNativeInvokeTransaction(
		gasPrice,
		gasLimit,
		ONT_ID_CONTRACT_VERSION,
		ONT_ID_CONTRACT_ADDRESS,
		"removeService",
		[]interface{}{
			&ServiceRemoveParam{
				OntId:     []byte(ontId),
				ServiceId: serviceId,
				Index:     index,
				Proof:     proof,
			},
		})
}

func (this *OntId) RemoveService(gasPrice, gasLimit uint64, payer, signer *Account, ontId string, serviceId []byte, index uint32,
	proof []byte, pk *Account) (common.Uint256, error) {
	tx, err := this.NewRemoveServiceTransaction(gasPrice, gasLimit, ontId, serviceId, index, proof)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	if payer != nil {
		this.ontSdk.SetPayer(tx, payer.Address)
		err = this.ontSdk.SignToTransaction(tx, payer)
		if err != nil {
			return common.UINT256_EMPTY, err
		}
	}
	err = this.ontSdk.SignToTransaction(tx, signer)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	err = this.ontSdk.SignToTransaction(tx, pk)
	if err != nil {
		return common.UINT256_EMPTY, err
	}

	return this.ontSdk.SendTransaction(tx)
}

func (this *OntId) NewAddContextTransaction(gasPrice, gasLimit uint64, ontId string, contexts [][]byte,
	index uint32, proof []byte) (*types.MutableTransaction, error) {
	type Context struct {
		OntId    []byte
		Contexts [][]byte
		Index    uint32
		Proof    []byte
	}

	return this.native.NewNativeInvokeTransaction(
		gasPrice,
		gasLimit,
		ONT_ID_CONTRACT_VERSION,
		ONT_ID_CONTRACT_ADDRESS,
		"addContext",
		[]interface{}{
			&Context{
				OntId:    []byte(ontId),
				Contexts: contexts,
				Index:    index,
				Proof:    proof,
			},
		})
}

func (this *OntId) AddContext(gasPrice, gasLimit uint64, payer, signer *Account, ontId string, contexts [][]byte,
	index uint32, proof []byte, pk *Account) (common.Uint256, error) {
	tx, err := this.NewAddContextTransaction(gasPrice, gasLimit, ontId, contexts, index, proof)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	if payer != nil {
		this.ontSdk.SetPayer(tx, payer.Address)
		err = this.ontSdk.SignToTransaction(tx, payer)
		if err != nil {
			return common.UINT256_EMPTY, err
		}
	}
	err = this.ontSdk.SignToTransaction(tx, signer)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	err = this.ontSdk.SignToTransaction(tx, pk)
	if err != nil {
		return common.UINT256_EMPTY, err
	}

	return this.ontSdk.SendTransaction(tx)
}

func (this *OntId) NewRemoveContextTransaction(gasPrice, gasLimit uint64, ontId string, contexts [][]byte,
	index uint32, proof []byte) (*types.MutableTransaction, error) {
	type Context struct {
		OntId    []byte
		Contexts [][]byte
		Index    uint32
		Proof    []byte
	}

	return this.native.NewNativeInvokeTransaction(
		gasPrice,
		gasLimit,
		ONT_ID_CONTRACT_VERSION,
		ONT_ID_CONTRACT_ADDRESS,
		"removeContext",
		[]interface{}{
			&Context{
				OntId:    []byte(ontId),
				Contexts: contexts,
				Index:    index,
				Proof:    proof,
			},
		})
}

func (this *OntId) RemoveContext(gasPrice, gasLimit uint64, payer, signer *Account, ontId string, contexts [][]byte,
	index uint32, proof []byte, pk *Account) (common.Uint256, error) {
	tx, err := this.NewRemoveContextTransaction(gasPrice, gasLimit, ontId, contexts, index, proof)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	if payer != nil {
		this.ontSdk.SetPayer(tx, payer.Address)
		err = this.ontSdk.SignToTransaction(tx, payer)
		if err != nil {
			return common.UINT256_EMPTY, err
		}
	}
	err = this.ontSdk.SignToTransaction(tx, signer)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	err = this.ontSdk.SignToTransaction(tx, pk)
	if err != nil {
		return common.UINT256_EMPTY, err
	}

	return this.ontSdk.SendTransaction(tx)
}

func (this *OntId) NewSetKeyAccessTransaction(gasPrice, gasLimit uint64, ontId string, setIndex uint32, access string,
	signIndex uint32, proof []byte) (*types.MutableTransaction, error) {
	type SetKeyAccessParam struct {
		OntId     []byte
		SetIndex  uint32
		Access    string
		SignIndex uint32
		Proof     []byte
	}

	return this.native.NewNativeInvokeTransaction(
		gasPrice,
		gasLimit,
		ONT_ID_CONTRACT_VERSION,
		ONT_ID_CONTRACT_ADDRESS,
		"setKeyAccess",
		[]interface{}{
			&SetKeyAccessParam{
				OntId:     []byte(ontId),
				SetIndex:  setIndex,
				Access:    access,
				SignIndex: signIndex,
				Proof:     proof,
			},
		})
}

func (this *OntId) SetKeyAccess(gasPrice, gasLimit uint64, payer, signer *Account, ontId string, setIndex uint32,
	access string, signIndex uint32, proof []byte, pk *Account) (common.Uint256, error) {
	tx, err := this.NewSetKeyAccessTransaction(gasPrice, gasLimit, ontId, setIndex, access, signIndex, proof)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	if payer != nil {
		this.ontSdk.SetPayer(tx, payer.Address)
		err = this.ontSdk.SignToTransaction(tx, payer)
		if err != nil {
			return common.UINT256_EMPTY, err
		}
	}
	err = this.ontSdk.SignToTransaction(tx, signer)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	err = this.ontSdk.SignToTransaction(tx, pk)
	if err != nil {
		return common.UINT256_EMPTY, err
	}

	return this.ontSdk.SendTransaction(tx)
}

func (this *OntId) GetAttributes(ontId string) ([]byte, error) {
	preResult, err := this.native.PreExecInvokeNativeContract(
		ONT_ID_CONTRACT_ADDRESS,
		ONT_ID_CONTRACT_VERSION,
		"getAttributes",
		[]interface{}{ontId})
	if err != nil {
		return nil, err
	}
	data, err := preResult.Result.ToByteArray()
	if err != nil {
		return nil, fmt.Errorf("ToByteArray error:%s", err)
	}
	return data, nil
}

func (this *OntId) VerifySignature(ontId string, keyIndex int, account *Account) (bool, error) {
	tx, err := this.native.NewNativeInvokeTransaction(
		0, 0,
		ONT_ID_CONTRACT_VERSION,
		ONT_ID_CONTRACT_ADDRESS,
		"verifySignature",
		[]interface{}{ontId, keyIndex})
	if err != nil {
		return false, err
	}
	err = this.ontSdk.SignToTransaction(tx, account)
	if err != nil {
		return false, err
	}
	preResult, err := this.ontSdk.PreExecTransaction(tx)
	if err != nil {
		return false, err
	}
	return preResult.Result.ToBool()
}

func (this *OntId) VerifySingleController(ontId string, keyIndex uint32, account *Account) (bool, error) {
	tx, err := this.native.NewNativeInvokeTransaction(
		0, 0,
		ONT_ID_CONTRACT_VERSION,
		ONT_ID_CONTRACT_ADDRESS,
		"verifyController",
		[]interface{}{ontId, keyIndex})
	if err != nil {
		return false, err
	}
	err = this.ontSdk.SignToTransaction(tx, account)
	if err != nil {
		return false, err
	}
	preResult, err := this.ontSdk.PreExecTransaction(tx)
	if err != nil {
		return false, err
	}
	return preResult.Result.ToBool()
}

func (this *OntId) VerifyMultiController(ontId string, signers []ontid.Signer, accounts []*Account) (bool, error) {
	s := ontid.SerializeSigners(signers)
	tx, err := this.native.NewNativeInvokeTransaction(
		0, 0,
		ONT_ID_CONTRACT_VERSION,
		ONT_ID_CONTRACT_ADDRESS,
		"verifyController",
		[]interface{}{ontId, s})
	if err != nil {
		return false, err
	}
	for _, account := range accounts {
		err = this.ontSdk.SignToTransaction(tx, account)
		if err != nil {
			return false, err
		}
	}
	preResult, err := this.ontSdk.PreExecTransaction(tx)
	if err != nil {
		return false, err
	}
	return preResult.Result.ToBool()
}

func (this *OntId) GetPublicKeys(ontId string) ([]byte, error) {
	preResult, err := this.native.PreExecInvokeNativeContract(
		ONT_ID_CONTRACT_ADDRESS,
		ONT_ID_CONTRACT_VERSION,
		"getPublicKeys",
		[]interface{}{
			ontId,
		})
	if err != nil {
		return nil, err
	}
	data, err := preResult.Result.ToByteArray()
	if err != nil {
		return nil, err
	}
	return data, nil
}

func (this *OntId) GetService(ontId string, serviceId []byte) ([]byte, error) {
	preResult, err := this.native.PreExecInvokeNativeContract(
		ONT_ID_CONTRACT_ADDRESS,
		ONT_ID_CONTRACT_VERSION,
		"getService",
		[]interface{}{
			[]byte(ontId),
			serviceId,
		})
	if err != nil {
		return nil, err
	}
	data, err := preResult.Result.ToByteArray()
	if err != nil {
		return nil, err
	}
	return data, nil
}

func (this *OntId) GetKeyState(ontId string, keyIndex int) (string, error) {
	type keyState struct {
		OntId    string
		KeyIndex int
	}
	preResult, err := this.native.PreExecInvokeNativeContract(
		ONT_ID_CONTRACT_ADDRESS,
		ONT_ID_CONTRACT_VERSION,
		"getKeyState",
		[]interface{}{
			&keyState{
				OntId:    ontId,
				KeyIndex: keyIndex,
			},
		})
	if err != nil {
		return "", err
	}
	return preResult.Result.ToString()
}

func (this *OntId) GetController(ontId string) ([]byte, error) {
	preResult, err := this.native.PreExecInvokeNativeContract(
		ONT_ID_CONTRACT_ADDRESS,
		ONT_ID_CONTRACT_VERSION,
		"getController",
		[]interface{}{
			[]byte(ontId),
		})
	if err != nil {
		return nil, err
	}
	data, err := preResult.Result.ToByteArray()
	if err != nil {
		return nil, err
	}
	return data, nil
}

func (this *OntId) GetDocument(ontId string) ([]byte, error) {
	preResult, err := this.native.PreExecInvokeNativeContract(
		ONT_ID_CONTRACT_ADDRESS,
		ONT_ID_CONTRACT_VERSION,
		"getDocument",
		[]interface{}{
			[]byte(ontId),
		})
	if err != nil {
		return nil, err
	}
	data, err := preResult.Result.ToByteArray()
	if err != nil {
		return nil, err
	}
	return data, nil
}

type GlobalParam struct {
	ontSdk *OntologySdk
	native *NativeContract
}

func (this *GlobalParam) GetGlobalParams(params []string) (map[string]string, error) {
	preResult, err := this.native.PreExecInvokeNativeContract(
		GLOABL_PARAMS_CONTRACT_ADDRESS,
		GLOBAL_PARAMS_CONTRACT_VERSION,
		global_params.GET_GLOBAL_PARAM_NAME,
		[]interface{}{params})
	if err != nil {
		return nil, err
	}
	results, err := preResult.Result.ToByteArray()
	if err != nil {
		return nil, err
	}
	queryParams := new(global_params.Params)
	err = queryParams.Deserialization(common.NewZeroCopySource(results))
	if err != nil {
		return nil, err
	}
	globalParams := make(map[string]string, len(params))
	for _, param := range params {
		index, values := queryParams.GetParam(param)
		if index < 0 {
			continue
		}
		globalParams[param] = values.Value
	}
	return globalParams, nil
}

func (this *GlobalParam) NewSetGlobalParamsTransaction(gasPrice, gasLimit uint64, params map[string]string) (*types.MutableTransaction, error) {
	var globalParams global_params.Params
	for k, v := range params {
		globalParams.SetParam(global_params.Param{Key: k, Value: v})
	}
	return this.native.NewNativeInvokeTransaction(
		gasPrice,
		gasLimit,
		GLOBAL_PARAMS_CONTRACT_VERSION,
		GLOABL_PARAMS_CONTRACT_ADDRESS,
		global_params.SET_GLOBAL_PARAM_NAME,
		[]interface{}{globalParams})
}

func (this *GlobalParam) SetGlobalParams(gasPrice, gasLimit uint64, payer, signer *Account, params map[string]string) (common.Uint256, error) {
	tx, err := this.NewSetGlobalParamsTransaction(gasPrice, gasLimit, params)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	if payer != nil {
		this.ontSdk.SetPayer(tx, payer.Address)
		err = this.ontSdk.SignToTransaction(tx, payer)
		if err != nil {
			return common.UINT256_EMPTY, err
		}
	}
	err = this.ontSdk.SignToTransaction(tx, signer)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	return this.ontSdk.SendTransaction(tx)
}

func (this *GlobalParam) NewTransferAdminTransaction(gasPrice, gasLimit uint64, newAdmin common.Address) (*types.MutableTransaction, error) {
	return this.native.NewNativeInvokeTransaction(
		gasPrice,
		gasLimit,
		GLOBAL_PARAMS_CONTRACT_VERSION,
		GLOABL_PARAMS_CONTRACT_ADDRESS,
		global_params.TRANSFER_ADMIN_NAME,
		[]interface{}{newAdmin})
}

func (this *GlobalParam) TransferAdmin(gasPrice, gasLimit uint64, payer, signer *Account, newAdmin common.Address) (common.Uint256, error) {
	tx, err := this.NewTransferAdminTransaction(gasPrice, gasLimit, newAdmin)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	if payer != nil {
		this.ontSdk.SetPayer(tx, payer.Address)
		err = this.ontSdk.SignToTransaction(tx, payer)
		if err != nil {
			return common.UINT256_EMPTY, err
		}
	}
	err = this.ontSdk.SignToTransaction(tx, signer)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	return this.ontSdk.SendTransaction(tx)
}

func (this *GlobalParam) NewAcceptAdminTransaction(gasPrice, gasLimit uint64, admin common.Address) (*types.MutableTransaction, error) {
	return this.native.NewNativeInvokeTransaction(
		gasPrice,
		gasLimit,
		GLOBAL_PARAMS_CONTRACT_VERSION,
		GLOABL_PARAMS_CONTRACT_ADDRESS,
		global_params.ACCEPT_ADMIN_NAME,
		[]interface{}{admin})
}

func (this *GlobalParam) AcceptAdmin(gasPrice, gasLimit uint64, payer, signer *Account) (common.Uint256, error) {
	tx, err := this.NewAcceptAdminTransaction(gasPrice, gasLimit, signer.Address)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	if payer != nil {
		this.ontSdk.SetPayer(tx, payer.Address)
		err = this.ontSdk.SignToTransaction(tx, payer)
		if err != nil {
			return common.UINT256_EMPTY, err
		}
	}
	err = this.ontSdk.SignToTransaction(tx, signer)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	return this.ontSdk.SendTransaction(tx)
}

func (this *GlobalParam) NewSetOperatorTransaction(gasPrice, gasLimit uint64, operator common.Address) (*types.MutableTransaction, error) {
	return this.native.NewNativeInvokeTransaction(
		gasPrice,
		gasLimit,
		GLOBAL_PARAMS_CONTRACT_VERSION,
		GLOABL_PARAMS_CONTRACT_ADDRESS,
		global_params.SET_OPERATOR,
		[]interface{}{operator},
	)
}

func (this *GlobalParam) SetOperator(gasPrice, gasLimit uint64, payer, signer *Account, operator common.Address) (common.Uint256, error) {
	tx, err := this.NewSetOperatorTransaction(gasPrice, gasLimit, operator)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	if payer != nil {
		this.ontSdk.SetPayer(tx, payer.Address)
		err = this.ontSdk.SignToTransaction(tx, payer)
		if err != nil {
			return common.UINT256_EMPTY, err
		}
	}
	err = this.ontSdk.SignToTransaction(tx, signer)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	return this.ontSdk.SendTransaction(tx)
}

func (this *GlobalParam) NewCreateSnapshotTransaction(gasPrice, gasLimit uint64) (*types.MutableTransaction, error) {
	return this.native.NewNativeInvokeTransaction(
		gasPrice,
		gasLimit,
		GLOBAL_PARAMS_CONTRACT_VERSION,
		GLOABL_PARAMS_CONTRACT_ADDRESS,
		global_params.CREATE_SNAPSHOT_NAME,
		[]interface{}{},
	)
}

func (this *GlobalParam) CreateSnapshot(gasPrice, gasLimit uint64, payer, signer *Account) (common.Uint256, error) {
	tx, err := this.NewCreateSnapshotTransaction(gasPrice, gasLimit)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	if payer != nil {
		this.ontSdk.SetPayer(tx, payer.Address)
		err = this.ontSdk.SignToTransaction(tx, payer)
		if err != nil {
			return common.UINT256_EMPTY, err
		}
	}
	err = this.ontSdk.SignToTransaction(tx, signer)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	return this.ontSdk.SendTransaction(tx)
}

type Auth struct {
	ontSdk *OntologySdk
	native *NativeContract
}

func (this *Auth) NewAssignFuncsToRoleTransaction(gasPrice, gasLimit uint64, contractAddress common.Address, adminId, role []byte, funcNames []string, keyIndex int) (*types.MutableTransaction, error) {
	return this.native.NewNativeInvokeTransaction(
		gasPrice,
		gasLimit,
		AUTH_CONTRACT_VERSION,
		AUTH_CONTRACT_ADDRESS,
		"assignFuncsToRole",
		[]interface{}{
			contractAddress,
			adminId,
			role,
			funcNames,
			keyIndex,
		})
}

func (this *Auth) AssignFuncsToRole(gasPrice, gasLimit uint64, contractAddress common.Address, payer, signer *Account, adminId, role []byte, funcNames []string, keyIndex int) (common.Uint256, error) {
	tx, err := this.NewAssignFuncsToRoleTransaction(gasPrice, gasLimit, contractAddress, adminId, role, funcNames, keyIndex)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	if payer != nil {
		this.ontSdk.SetPayer(tx, payer.Address)
		err = this.ontSdk.SignToTransaction(tx, payer)
		if err != nil {
			return common.UINT256_EMPTY, err
		}
	}
	err = this.ontSdk.SignToTransaction(tx, signer)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	return this.ontSdk.SendTransaction(tx)
}

func (this *Auth) NewDelegateTransaction(gasPrice, gasLimit uint64, contractAddress common.Address, from, to, role []byte, period, level, keyIndex int) (*types.MutableTransaction, error) {
	return this.native.NewNativeInvokeTransaction(
		gasPrice,
		gasLimit,
		AUTH_CONTRACT_VERSION,
		AUTH_CONTRACT_ADDRESS,
		"delegate",
		[]interface{}{
			contractAddress,
			from,
			to,
			role,
			period,
			level,
			keyIndex,
		})
}

func (this *Auth) Delegate(gasPrice, gasLimit uint64, payer, signer *Account, contractAddress common.Address, from, to, role []byte, period, level, keyIndex int) (common.Uint256, error) {
	tx, err := this.NewDelegateTransaction(gasPrice, gasLimit, contractAddress, from, to, role, period, level, keyIndex)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	if payer != nil {
		this.ontSdk.SetPayer(tx, payer.Address)
		err = this.ontSdk.SignToTransaction(tx, payer)
		if err != nil {
			return common.UINT256_EMPTY, err
		}
	}
	err = this.ontSdk.SignToTransaction(tx, signer)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	return this.ontSdk.SendTransaction(tx)
}

func (this *Auth) NewWithdrawTransaction(gasPrice, gasLimit uint64, contractAddress common.Address, initiator, delegate, role []byte, keyIndex int) (*types.MutableTransaction, error) {
	return this.native.NewNativeInvokeTransaction(
		gasPrice,
		gasLimit,
		AUTH_CONTRACT_VERSION,
		AUTH_CONTRACT_ADDRESS,
		"withdraw",
		[]interface{}{
			contractAddress,
			initiator,
			delegate,
			role,
			keyIndex,
		})
}

func (this *Auth) Withdraw(gasPrice, gasLimit uint64, payer, signer *Account, contractAddress common.Address, initiator, delegate, role []byte, keyIndex int) (common.Uint256, error) {
	tx, err := this.NewWithdrawTransaction(gasPrice, gasLimit, contractAddress, initiator, delegate, role, keyIndex)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	if payer != nil {
		this.ontSdk.SetPayer(tx, payer.Address)
		err = this.ontSdk.SignToTransaction(tx, payer)
		if err != nil {
			return common.UINT256_EMPTY, err
		}
	}
	err = this.ontSdk.SignToTransaction(tx, signer)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	return this.ontSdk.SendTransaction(tx)
}

func (this *Auth) NewAssignOntIDsToRoleTransaction(gasPrice, gasLimit uint64, contractAddress common.Address, admontId, role []byte, persons [][]byte, keyIndex int) (*types.MutableTransaction, error) {
	return this.native.NewNativeInvokeTransaction(
		gasPrice,
		gasLimit,
		AUTH_CONTRACT_VERSION,
		AUTH_CONTRACT_ADDRESS,
		"assignOntIDsToRole",
		[]interface{}{
			contractAddress,
			admontId,
			role,
			persons,
			keyIndex,
		})
}

func (this *Auth) AssignOntIDsToRole(gasPrice, gasLimit uint64, payer, signer *Account, contractAddress common.Address, admontId, role []byte, persons [][]byte, keyIndex int) (common.Uint256, error) {
	tx, err := this.NewAssignOntIDsToRoleTransaction(gasPrice, gasLimit, contractAddress, admontId, role, persons, keyIndex)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	if payer != nil {
		this.ontSdk.SetPayer(tx, payer.Address)
		err = this.ontSdk.SignToTransaction(tx, payer)
		if err != nil {
			return common.UINT256_EMPTY, err
		}
	}
	err = this.ontSdk.SignToTransaction(tx, signer)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	return this.ontSdk.SendTransaction(tx)
}

func (this *Auth) NewTransferTransaction(gasPrice, gasLimit uint64, contractAddress common.Address, newAdminId []byte, keyIndex int) (*types.MutableTransaction, error) {
	return this.native.NewNativeInvokeTransaction(
		gasPrice,
		gasLimit,
		AUTH_CONTRACT_VERSION,
		AUTH_CONTRACT_ADDRESS,
		"transfer",
		[]interface{}{
			contractAddress,
			newAdminId,
			keyIndex,
		})
}

func (this *Auth) Transfer(gasPrice, gasLimit uint64, payer, signer *Account, contractAddress common.Address, newAdminId []byte, keyIndex int) (common.Uint256, error) {
	tx, err := this.NewTransferTransaction(gasPrice, gasLimit, contractAddress, newAdminId, keyIndex)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	if payer != nil {
		this.ontSdk.SetPayer(tx, payer.Address)
		err = this.ontSdk.SignToTransaction(tx, payer)
		if err != nil {
			return common.UINT256_EMPTY, err
		}
	}
	err = this.ontSdk.SignToTransaction(tx, signer)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	return this.ontSdk.SendTransaction(tx)
}

func (this *Auth) NewVerifyTokenTransaction(gasPrice, gasLimit uint64, contractAddress common.Address, caller []byte, funcName string, keyIndex int) (*types.MutableTransaction, error) {
	return this.native.NewNativeInvokeTransaction(
		gasPrice,
		gasLimit,
		AUTH_CONTRACT_VERSION,
		AUTH_CONTRACT_ADDRESS,
		"verifyToken",
		[]interface{}{
			contractAddress,
			caller,
			funcName,
			keyIndex,
		})
}

func (this *Auth) VerifyToken(gasPrice, gasLimit uint64, payer, signer *Account, contractAddress common.Address, caller []byte, funcName string, keyIndex int) (common.Uint256, error) {
	tx, err := this.NewVerifyTokenTransaction(gasPrice, gasLimit, contractAddress, caller, funcName, keyIndex)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	if payer != nil {
		this.ontSdk.SetPayer(tx, payer.Address)
		err = this.ontSdk.SignToTransaction(tx, payer)
		if err != nil {
			return common.UINT256_EMPTY, err
		}
	}
	err = this.ontSdk.SignToTransaction(tx, signer)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	return this.ontSdk.SendTransaction(tx)
}
