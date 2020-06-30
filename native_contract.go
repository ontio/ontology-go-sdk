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
	"github.com/ontio/ontology/account"
	"github.com/ontio/ontology/common"
	"github.com/ontio/ontology/core/types"
	cutils "github.com/ontio/ontology/core/utils"
	"github.com/ontio/ontology/smartcontract/service/native/global_params"
	"github.com/ontio/ontology/smartcontract/service/native/ont"
	"github.com/ontio/ontology/smartcontract/service/native/ontid"
	nutils "github.com/ontio/ontology/smartcontract/service/native/utils"
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
	pubKey keypair.PublicKey) (*types.MutableTransaction, error) {
	type regIDWithPublicKey struct {
		OntId  string
		PubKey []byte
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
			},
		},
	)
}

func (this *OntId) RegIDWithPublicKey(gasPrice, gasLimit uint64, payer *Account, ontId string,
	signer *Account) (common.Uint256, error) {
	tx, err := this.NewRegIDWithPublicKeyTransaction(gasPrice, gasLimit, ontId, signer.PublicKey)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	this.ontSdk.SetPayer(tx, payer.Address)
	err = this.ontSdk.SignToTransaction(tx, payer)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	err = this.ontSdk.SignToTransaction(tx, signer)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	return this.ontSdk.SendTransaction(tx)
}

func SerializeGroup(g *ontid.Group) []byte {
	sink := common.NewZeroCopySink(nil)
	nutils.EncodeVarUint(sink, uint64(len(g.Members)))
	for _, m := range g.Members {
		switch t := m.(type) {
		case []byte:
			if !account.VerifyID(string(t)) {
				panic("invalid ont id format")
			}
			sink.WriteVarBytes(t)
		case *ontid.Group:
			sink.WriteVarBytes(SerializeGroup(t))
		default:
			panic("invalid member type")
		}
	}
	nutils.EncodeVarUint(sink, uint64(g.Threshold))
	return sink.Bytes()
}

func (this *OntId) NewRegIDWithControllerTransaction(gasPrice, gasLimit uint64, ontId string, controller *ontid.Group,
	signers []ontid.Signer) (*types.MutableTransaction, error) {
	c := SerializeGroup(controller)
	s := ontid.SerializeSigners(signers)
	type regIDWithController struct {
		OntId      string
		Controller []byte
		Signers    []byte
	}
	return this.native.NewNativeInvokeTransaction(
		gasPrice,
		gasLimit,
		ONT_ID_CONTRACT_VERSION,
		ONT_ID_CONTRACT_ADDRESS,
		"regIDWithController",
		[]interface{}{
			&regIDWithController{
				OntId:      ontId,
				Controller: c,
				Signers:    s,
			},
		},
	)
}

func (this *OntId) RegIDWithController(gasPrice, gasLimit uint64, payer *Account, ontId string,
	controller *ontid.Group, signers []ontid.Signer, controllerSigners []*Account) (common.Uint256, error) {
	tx, err := this.NewRegIDWithControllerTransaction(gasPrice, gasLimit, ontId, controller, signers)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	this.ontSdk.SetPayer(tx, payer.Address)
	err = this.ontSdk.SignToTransaction(tx, payer)
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

func (this *OntId) RevokeID(gasPrice, gasLimit uint64, payer *Account, ontId string,
	index uint32, signer *Account) (common.Uint256, error) {
	tx, err := this.NewRevokeIDTransaction(gasPrice, gasLimit, ontId, index)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	this.ontSdk.SetPayer(tx, payer.Address)
	err = this.ontSdk.SignToTransaction(tx, payer)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	err = this.ontSdk.SignToTransaction(tx, signer)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	return this.ontSdk.SendTransaction(tx)
}

func (this *OntId) NewRevokeIDByControllerTransaction(gasPrice, gasLimit uint64, ontId string, signers []ontid.Signer) (*types.MutableTransaction, error) {
	s := ontid.SerializeSigners(signers)
	type revokeIDByController struct {
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
			&revokeIDByController{
				OntId: ontId,
				S:     s,
			},
		},
	)
}

func (this *OntId) RevokeIDByController(gasPrice, gasLimit uint64, payer *Account, ontId string,
	signers []ontid.Signer, controllerSigners []*Account) (common.Uint256, error) {
	tx, err := this.NewRevokeIDByControllerTransaction(gasPrice, gasLimit, ontId, signers)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	this.ontSdk.SetPayer(tx, payer.Address)
	err = this.ontSdk.SignToTransaction(tx, payer)
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
	index uint32) (*types.MutableTransaction, error) {
	type removeController struct {
		OntId string
		Index uint32
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
			},
		},
	)
}

func (this *OntId) RemoveController(gasPrice, gasLimit uint64, payer *Account, ontId string,
	index uint32, signer *Account) (common.Uint256, error) {
	tx, err := this.NewRemoveControllerTransaction(gasPrice, gasLimit, ontId, index)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	this.ontSdk.SetPayer(tx, payer.Address)
	err = this.ontSdk.SignToTransaction(tx, payer)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	err = this.ontSdk.SignToTransaction(tx, signer)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	return this.ontSdk.SendTransaction(tx)
}

func (this *OntId) NewRegIDWithAttributesTransaction(gasPrice, gasLimit uint64, ontId string, pubKey keypair.PublicKey,
	attributes []*DDOAttribute) (*types.MutableTransaction, error) {
	type regIDWithAttribute struct {
		OntId      string
		PubKey     []byte
		Attributes []*DDOAttribute
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
			},
		},
	)
}

func (this *OntId) RegIDWithAttributes(gasPrice, gasLimit uint64, payer *Account, ontId string,
	attributes []*DDOAttribute, signer *Account) (common.Uint256, error) {
	tx, err := this.NewRegIDWithAttributesTransaction(gasPrice, gasLimit, ontId, signer.PublicKey, attributes)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	this.ontSdk.SetPayer(tx, payer.Address)
	err = this.ontSdk.SignToTransaction(tx, payer)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	err = this.ontSdk.SignToTransaction(tx, signer)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	return this.ontSdk.SendTransaction(tx)
}

func (this *OntId) NewAddKeyTransaction(gasPrice, gasLimit uint64, ontId string, newPubKey []byte, pubKey keypair.PublicKey,
	controller string) (*types.MutableTransaction, error) {
	type addKey struct {
		OntId      string
		NewPubKey  []byte
		PubKey     []byte
		Controller []byte
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
			},
		})
}

func (this *OntId) AddKey(gasPrice, gasLimit uint64, payer *Account, ontId string,
	newPubKey []byte, controller string, signer *Account) (common.Uint256, error) {
	tx, err := this.NewAddKeyTransaction(gasPrice, gasLimit, ontId, newPubKey, signer.PublicKey, controller)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	this.ontSdk.SetPayer(tx, payer.Address)
	err = this.ontSdk.SignToTransaction(tx, payer)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	err = this.ontSdk.SignToTransaction(tx, signer)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	return this.ontSdk.SendTransaction(tx)
}

func (this *OntId) NewAddKeyByIndexTransaction(gasPrice, gasLimit uint64, ontId string, newPubKey []byte, index uint32,
	controller string) (*types.MutableTransaction, error) {
	type addKeyByIndex struct {
		OntId      string
		NewPubKey  []byte
		Index      uint32
		Controller []byte
	}
	return this.native.NewNativeInvokeTransaction(
		gasPrice,
		gasLimit,
		ONT_ID_CONTRACT_VERSION,
		ONT_ID_CONTRACT_ADDRESS,
		"addKeyByIndex",
		[]interface{}{
			&addKeyByIndex{
				OntId:      ontId,
				NewPubKey:  newPubKey,
				Index:      index,
				Controller: []byte(controller),
			},
		})
}

func (this *OntId) AddKeyByIndex(gasPrice, gasLimit uint64, payer *Account, ontId string,
	newPubKey []byte, index uint32, controller string, signer *Account) (common.Uint256, error) {
	tx, err := this.NewAddKeyByIndexTransaction(gasPrice, gasLimit, ontId, newPubKey, index, controller)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	this.ontSdk.SetPayer(tx, payer.Address)
	err = this.ontSdk.SignToTransaction(tx, payer)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	err = this.ontSdk.SignToTransaction(tx, signer)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	return this.ontSdk.SendTransaction(tx)
}

func (this *OntId) NewRemoveKeyTransaction(gasPrice, gasLimit uint64, ontId string, removedPubKey []byte,
	pubKey keypair.PublicKey) (*types.MutableTransaction, error) {
	type removeKey struct {
		OntId      string
		RemovedKey []byte
		PubKey     []byte
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
			},
		},
	)
}

func (this *OntId) RemoveKey(gasPrice, gasLimit uint64, payer *Account, ontId string,
	removedPubKey []byte, signer *Account) (common.Uint256, error) {
	tx, err := this.NewRemoveKeyTransaction(gasPrice, gasLimit, ontId, removedPubKey, signer.PublicKey)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	this.ontSdk.SetPayer(tx, payer.Address)
	err = this.ontSdk.SignToTransaction(tx, payer)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	err = this.ontSdk.SignToTransaction(tx, signer)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	return this.ontSdk.SendTransaction(tx)
}

func (this *OntId) NewRemoveKeyByIndexTransaction(gasPrice, gasLimit uint64, ontId string, removedPubKey []byte,
	index uint32) (*types.MutableTransaction, error) {
	type removeKeyByIndex struct {
		OntId      string
		RemovedKey []byte
		Index      uint32
	}
	return this.native.NewNativeInvokeTransaction(
		gasPrice,
		gasLimit,
		ONT_ID_CONTRACT_VERSION,
		ONT_ID_CONTRACT_ADDRESS,
		"removeKeyByIndex",
		[]interface{}{
			&removeKeyByIndex{
				OntId:      ontId,
				RemovedKey: removedPubKey,
				Index:      index,
			},
		},
	)
}

func (this *OntId) RemoveKeyByIndex(gasPrice, gasLimit uint64, payer *Account, ontId string,
	removedPubKey []byte, index uint32, signer *Account) (common.Uint256, error) {
	tx, err := this.NewRemoveKeyByIndexTransaction(gasPrice, gasLimit, ontId, removedPubKey, index)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	this.ontSdk.SetPayer(tx, payer.Address)
	err = this.ontSdk.SignToTransaction(tx, payer)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	err = this.ontSdk.SignToTransaction(tx, signer)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	return this.ontSdk.SendTransaction(tx)
}

func (this *OntId) NewSetRecoveryTransaction(gasPrice, gasLimit uint64, ontId string, recovery *ontid.Group,
	index uint32) (*types.MutableTransaction, error) {
	r := SerializeGroup(recovery)
	type setRecovery struct {
		OntId    string
		Recovery []byte
		Index    uint32
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
			},
		})
}

func (this *OntId) SetRecovery(gasPrice, gasLimit uint64, payer *Account, ontId string, recovery *ontid.Group,
	index uint32, signer *Account) (common.Uint256, error) {
	tx, err := this.NewSetRecoveryTransaction(gasPrice, gasLimit, ontId, recovery, index)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	this.ontSdk.SetPayer(tx, payer.Address)
	err = this.ontSdk.SignToTransaction(tx, payer)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	err = this.ontSdk.SignToTransaction(tx, signer)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	return this.ontSdk.SendTransaction(tx)
}

func (this *OntId) NewUpdateRecoveryTransaction(gasPrice, gasLimit uint64, ontId string,
	newRecovery *ontid.Group, signers []ontid.Signer) (*types.MutableTransaction, error) {
	r := SerializeGroup(newRecovery)
	s := ontid.SerializeSigners(signers)
	type updateRecovery struct {
		OntId string
		R     []byte
		S     []byte
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
			},
		},
	)
}

func (this *OntId) UpdateRecovery(gasPrice, gasLimit uint64, payer *Account, ontId string,
	newRecovery *ontid.Group, signers []ontid.Signer, recoverySigners []*Account) (common.Uint256, error) {
	tx, err := this.NewUpdateRecoveryTransaction(gasPrice, gasLimit, ontId, newRecovery, signers)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	this.ontSdk.SetPayer(tx, payer.Address)
	err = this.ontSdk.SignToTransaction(tx, payer)
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

func (this *OntId) NewRemoveRecoveryTransaction(gasPrice, gasLimit uint64, ontId string, index uint32) (*types.MutableTransaction, error) {
	type removeRecovery struct {
		OntId string
		Index uint32
	}
	return this.native.NewNativeInvokeTransaction(
		gasPrice,
		gasLimit,
		ONT_ID_CONTRACT_VERSION,
		ONT_ID_CONTRACT_ADDRESS,
		"removeRecovery",
		[]interface{}{
			&removeRecovery{
				OntId: ontId,
				Index: index,
			},
		})
}

func (this *OntId) RemoveRecovery(gasPrice, gasLimit uint64, payer *Account, ontId string,
	index uint32, signer *Account) (common.Uint256, error) {
	tx, err := this.NewRemoveRecoveryTransaction(gasPrice, gasLimit, ontId, index)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	this.ontSdk.SetPayer(tx, payer.Address)
	err = this.ontSdk.SignToTransaction(tx, payer)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	err = this.ontSdk.SignToTransaction(tx, signer)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	return this.ontSdk.SendTransaction(tx)
}

func (this *OntId) NewAddKeyByControllerTransaction(gasPrice, gasLimit uint64, ontId string, publicKey []byte,
	signers []ontid.Signer, controller string) (*types.MutableTransaction, error) {
	s := ontid.SerializeSigners(signers)
	type addKeyByController struct {
		OntId      string
		PublicKey  []byte
		Signers    []byte
		Controller []byte
	}
	return this.native.NewNativeInvokeTransaction(
		gasPrice,
		gasLimit,
		ONT_ID_CONTRACT_VERSION,
		ONT_ID_CONTRACT_ADDRESS,
		"addKeyByController",
		[]interface{}{
			&addKeyByController{
				OntId:      ontId,
				PublicKey:  publicKey,
				Signers:    s,
				Controller: []byte(controller),
			},
		},
	)
}

func (this *OntId) AddKeyByController(gasPrice, gasLimit uint64, payer *Account, ontId string,
	publicKey []byte, signers []ontid.Signer, controller string, controllerSigners []*Account) (common.Uint256, error) {
	tx, err := this.NewAddKeyByControllerTransaction(gasPrice, gasLimit, ontId, publicKey, signers, controller)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	this.ontSdk.SetPayer(tx, payer.Address)
	err = this.ontSdk.SignToTransaction(tx, payer)
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

func (this *OntId) NewRemoveKeyByControllerTransaction(gasPrice, gasLimit uint64, ontId string, publicKeyIndex []byte,
	signers []ontid.Signer) (*types.MutableTransaction, error) {
	s := ontid.SerializeSigners(signers)
	type removeKeyByController struct {
		OntId          string
		publicKeyIndex []byte
		Signers        []byte
	}
	return this.native.NewNativeInvokeTransaction(
		gasPrice,
		gasLimit,
		ONT_ID_CONTRACT_VERSION,
		ONT_ID_CONTRACT_ADDRESS,
		"removeKeyByController",
		[]interface{}{
			&removeKeyByController{
				OntId:          ontId,
				publicKeyIndex: publicKeyIndex,
				Signers:        s,
			},
		},
	)
}

func (this *OntId) RemoveKeyByController(gasPrice, gasLimit uint64, payer *Account, ontId string,
	publicKeyIndex []byte, signers []ontid.Signer, controllerSigners []*Account) (common.Uint256, error) {
	tx, err := this.NewRemoveKeyByControllerTransaction(gasPrice, gasLimit, ontId, publicKeyIndex, signers)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	this.ontSdk.SetPayer(tx, payer.Address)
	err = this.ontSdk.SignToTransaction(tx, payer)
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
	publicKey []byte, signers []ontid.Signer, controller string) (*types.MutableTransaction, error) {
	s := ontid.SerializeSigners(signers)
	type addKeyByRecovery struct {
		OntId      string
		PublicKey  []byte
		S          []byte
		Controller []byte
	}
	return this.native.NewNativeInvokeTransaction(
		gasPrice,
		gasLimit,
		ONT_ID_CONTRACT_VERSION,
		ONT_ID_CONTRACT_ADDRESS,
		"addKeyByRecovery",
		[]interface{}{
			&addKeyByRecovery{
				OntId:      ontId,
				PublicKey:  publicKey,
				S:          s,
				Controller: []byte(controller),
			},
		},
	)
}

func (this *OntId) AddKeyByRecovery(gasPrice, gasLimit uint64, payer *Account, ontId string,
	publicKey []byte, signers []ontid.Signer, controller string, recoverySigners []*Account) (common.Uint256, error) {
	tx, err := this.NewAddKeyByRecoveryTransaction(gasPrice, gasLimit, ontId, publicKey, signers, controller)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	this.ontSdk.SetPayer(tx, payer.Address)
	err = this.ontSdk.SignToTransaction(tx, payer)
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
	publicKeyIndex uint32, signers []ontid.Signer) (*types.MutableTransaction, error) {
	s := ontid.SerializeSigners(signers)
	type removeKeyByRecovery struct {
		OntId          string
		PublicKeyIndex uint32
		S              []byte
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
			},
		},
	)
}

func (this *OntId) RemoveKeyByRecovery(gasPrice, gasLimit uint64, payer *Account, ontId string,
	publicKeyIndex uint32, signers []ontid.Signer, recoverySigners []*Account) (common.Uint256, error) {
	tx, err := this.NewRemoveKeyByRecoveryTransaction(gasPrice, gasLimit, ontId, publicKeyIndex, signers)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	this.ontSdk.SetPayer(tx, payer.Address)
	err = this.ontSdk.SignToTransaction(tx, payer)
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
	pubKey keypair.PublicKey) (*types.MutableTransaction, error) {
	type addAttributes struct {
		OntId      string
		Attributes []*DDOAttribute
		PubKey     []byte
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
			},
		})
}

func (this *OntId) AddAttributes(gasPrice, gasLimit uint64, payer *Account, ontId string,
	attributes []*DDOAttribute, signer *Account) (common.Uint256, error) {
	tx, err := this.NewAddAttributesTransaction(gasPrice, gasLimit, ontId, attributes, signer.PublicKey)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	this.ontSdk.SetPayer(tx, payer.Address)
	err = this.ontSdk.SignToTransaction(tx, payer)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	err = this.ontSdk.SignToTransaction(tx, signer)
	if err != nil {
		return common.UINT256_EMPTY, err
	}

	return this.ontSdk.SendTransaction(tx)
}

func (this *OntId) NewAddAttributesByIndexTransaction(gasPrice, gasLimit uint64, ontId string, attributes []*DDOAttribute,
	index uint32) (*types.MutableTransaction, error) {
	type addAttributesByIndex struct {
		OntId      string
		Attributes []*DDOAttribute
		Index      uint32
	}
	return this.native.NewNativeInvokeTransaction(
		gasPrice,
		gasLimit,
		ONT_ID_CONTRACT_VERSION,
		ONT_ID_CONTRACT_ADDRESS,
		"addAttributesByIndex",
		[]interface{}{
			&addAttributesByIndex{
				OntId:      ontId,
				Attributes: attributes,
				Index:      index,
			},
		})
}

func (this *OntId) AddAttributesByIndex(gasPrice, gasLimit uint64, payer *Account, ontId string,
	attributes []*DDOAttribute, index uint32, signer *Account) (common.Uint256, error) {
	tx, err := this.NewAddAttributesByIndexTransaction(gasPrice, gasLimit, ontId, attributes, index)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	this.ontSdk.SetPayer(tx, payer.Address)
	err = this.ontSdk.SignToTransaction(tx, payer)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	err = this.ontSdk.SignToTransaction(tx, signer)
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

func (this *OntId) RemoveAttribute(gasPrice, gasLimit uint64, payer *Account, ontId string, removeKey []byte,
	signer *Account) (common.Uint256, error) {
	tx, err := this.NewRemoveAttributeTransaction(gasPrice, gasLimit, ontId, removeKey, signer.PublicKey)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	this.ontSdk.SetPayer(tx, payer.Address)
	err = this.ontSdk.SignToTransaction(tx, payer)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	err = this.ontSdk.SignToTransaction(tx, signer)
	if err != nil {
		return common.UINT256_EMPTY, err
	}

	return this.ontSdk.SendTransaction(tx)
}

func (this *OntId) NewRemoveAttributeByIndexTransaction(gasPrice, gasLimit uint64, ontId string, key []byte, index uint32) (*types.MutableTransaction, error) {
	type removeAttributeByIndex struct {
		OntId string
		Key   []byte
		Index uint32
	}
	return this.native.NewNativeInvokeTransaction(
		gasPrice,
		gasLimit,
		ONT_ID_CONTRACT_VERSION,
		ONT_ID_CONTRACT_ADDRESS,
		"removeAttributeByIndex",
		[]interface{}{
			&removeAttributeByIndex{
				OntId: ontId,
				Key:   key,
				Index: index,
			},
		})
}

func (this *OntId) RemoveAttributeByIndex(gasPrice, gasLimit uint64, payer *Account, ontId string, removeKey []byte,
	index uint32, signer *Account) (common.Uint256, error) {
	tx, err := this.NewRemoveAttributeByIndexTransaction(gasPrice, gasLimit, ontId, removeKey, index)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	this.ontSdk.SetPayer(tx, payer.Address)
	err = this.ontSdk.SignToTransaction(tx, payer)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	err = this.ontSdk.SignToTransaction(tx, signer)
	if err != nil {
		return common.UINT256_EMPTY, err
	}

	return this.ontSdk.SendTransaction(tx)
}

func (this *OntId) NewAddAttributesByControllerTransaction(gasPrice, gasLimit uint64, ontId string, attributes []*DDOAttribute,
	signers []ontid.Signer) (*types.MutableTransaction, error) {
	s := ontid.SerializeSigners(signers)
	type addAttributesByController struct {
		OntId      string
		Attributes []*DDOAttribute
		Signers    []byte
	}
	return this.native.NewNativeInvokeTransaction(
		gasPrice,
		gasLimit,
		ONT_ID_CONTRACT_VERSION,
		ONT_ID_CONTRACT_ADDRESS,
		"addAttributesByController",
		[]interface{}{
			&addAttributesByController{
				OntId:      ontId,
				Attributes: attributes,
				Signers:    s,
			},
		},
	)
}

func (this *OntId) AddAttributesByController(gasPrice, gasLimit uint64, payer *Account, ontId string,
	attributes []*DDOAttribute, signers []ontid.Signer, controllerSigners []*Account) (common.Uint256, error) {
	tx, err := this.NewAddAttributesByControllerTransaction(gasPrice, gasLimit, ontId, attributes, signers)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	this.ontSdk.SetPayer(tx, payer.Address)
	err = this.ontSdk.SignToTransaction(tx, payer)
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

func (this *OntId) NewRemoveAttributesByControllerTransaction(gasPrice, gasLimit uint64, ontId string, key []byte,
	signers []ontid.Signer) (*types.MutableTransaction, error) {
	s := ontid.SerializeSigners(signers)
	type removeAttributesByController struct {
		OntId   string
		Key     []byte
		Signers []byte
	}
	return this.native.NewNativeInvokeTransaction(
		gasPrice,
		gasLimit,
		ONT_ID_CONTRACT_VERSION,
		ONT_ID_CONTRACT_ADDRESS,
		"removeAttributesByController",
		[]interface{}{
			&removeAttributesByController{
				OntId:   ontId,
				Key:     key,
				Signers: s,
			},
		},
	)
}

func (this *OntId) RemoveAttributesByController(gasPrice, gasLimit uint64, payer *Account, ontId string,
	key []byte, signers []ontid.Signer, controllerSigners []*Account) (common.Uint256, error) {
	tx, err := this.NewRemoveAttributesByControllerTransaction(gasPrice, gasLimit, ontId, key, signers)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	this.ontSdk.SetPayer(tx, payer.Address)
	err = this.ontSdk.SignToTransaction(tx, payer)
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

func (this *OntId) NewAddNewAuthKeyTransaction(gasPrice, gasLimit uint64, ontId string, publicKey []byte,
	controller string, signIndex uint32) (*types.MutableTransaction, error) {
	type NewPublicKey struct {
		Key        []byte
		Controller []byte
	}
	type AddNewAuthKeyParam struct {
		OntId        []byte
		NewPublicKey *NewPublicKey
		SignIndex    uint32
	}

	return this.native.NewNativeInvokeTransaction(
		gasPrice,
		gasLimit,
		ONT_ID_CONTRACT_VERSION,
		ONT_ID_CONTRACT_ADDRESS,
		"addNewAuthKey",
		[]interface{}{
			&AddNewAuthKeyParam{
				OntId: []byte(ontId),
				NewPublicKey: &NewPublicKey{
					Key:        publicKey,
					Controller: []byte(controller),
				},
				SignIndex: signIndex,
			},
		})
}

func (this *OntId) AddNewAuthKey(gasPrice, gasLimit uint64, payer *Account, ontId string,
	publicKey []byte, controller string, signIndex uint32, signer *Account) (common.Uint256, error) {
	tx, err := this.NewAddNewAuthKeyTransaction(gasPrice, gasLimit, ontId, publicKey, controller, signIndex)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	this.ontSdk.SetPayer(tx, payer.Address)
	err = this.ontSdk.SignToTransaction(tx, payer)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	err = this.ontSdk.SignToTransaction(tx, signer)
	if err != nil {
		return common.UINT256_EMPTY, err
	}

	return this.ontSdk.SendTransaction(tx)
}

func (this *OntId) NewAddNewAuthKeyByRecoveryTransaction(gasPrice, gasLimit uint64, ontId string, publicKey []byte,
	controller string, signers []ontid.Signer) (*types.MutableTransaction, error) {
	s := ontid.SerializeSigners(signers)
	type NewPublicKey struct {
		Key        []byte
		Controller []byte
	}
	type AddNewAuthKeyByRecoveryParam struct {
		OntId        []byte
		NewPublicKey *NewPublicKey
		Signers      []byte
	}

	return this.native.NewNativeInvokeTransaction(
		gasPrice,
		gasLimit,
		ONT_ID_CONTRACT_VERSION,
		ONT_ID_CONTRACT_ADDRESS,
		"addNewAuthKeyByRecovery",
		[]interface{}{
			&AddNewAuthKeyByRecoveryParam{
				OntId: []byte(ontId),
				NewPublicKey: &NewPublicKey{
					Key:        publicKey,
					Controller: []byte(controller),
				},
				Signers: s,
			},
		})
}

func (this *OntId) AddNewAuthKeyByRecovery(gasPrice, gasLimit uint64, payer *Account, ontId string,
	publicKey []byte, controller string, signers []ontid.Signer, recoverySigners []*Account) (common.Uint256, error) {
	tx, err := this.NewAddNewAuthKeyByRecoveryTransaction(gasPrice, gasLimit, ontId, publicKey, controller, signers)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	this.ontSdk.SetPayer(tx, payer.Address)
	err = this.ontSdk.SignToTransaction(tx, payer)
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

func (this *OntId) NewAddNewAuthKeyByControllerTransaction(gasPrice, gasLimit uint64, ontId string, publicKey []byte,
	controller string, signers []ontid.Signer) (*types.MutableTransaction, error) {
	s := ontid.SerializeSigners(signers)
	type NewPublicKey struct {
		Key        []byte
		Controller []byte
	}
	type AddNewAuthKeyByControllerParam struct {
		OntId        []byte
		NewPublicKey *NewPublicKey
		Signers      []byte
	}

	return this.native.NewNativeInvokeTransaction(
		gasPrice,
		gasLimit,
		ONT_ID_CONTRACT_VERSION,
		ONT_ID_CONTRACT_ADDRESS,
		"addNewAuthKeyByController",
		[]interface{}{
			&AddNewAuthKeyByControllerParam{
				OntId: []byte(ontId),
				NewPublicKey: &NewPublicKey{
					Key:        publicKey,
					Controller: []byte(controller),
				},
				Signers: s,
			},
		})
}

func (this *OntId) AddNewAuthKeyByController(gasPrice, gasLimit uint64, payer *Account, ontId string,
	publicKey []byte, controller string, signers []ontid.Signer, controllerSigners []*Account) (common.Uint256, error) {
	tx, err := this.NewAddNewAuthKeyByControllerTransaction(gasPrice, gasLimit, ontId, publicKey, controller, signers)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	this.ontSdk.SetPayer(tx, payer.Address)
	err = this.ontSdk.SignToTransaction(tx, payer)
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

func (this *OntId) NewSetAuthKeyTransaction(gasPrice, gasLimit uint64, ontId string, index,
	signIndex uint32) (*types.MutableTransaction, error) {
	type AddNewAuthKeyParam struct {
		OntId     []byte
		Index     uint32
		SignIndex uint32
	}

	return this.native.NewNativeInvokeTransaction(
		gasPrice,
		gasLimit,
		ONT_ID_CONTRACT_VERSION,
		ONT_ID_CONTRACT_ADDRESS,
		"addNewAuthKey",
		[]interface{}{
			&AddNewAuthKeyParam{
				OntId:     []byte(ontId),
				Index:     index,
				SignIndex: signIndex,
			},
		})
}

func (this *OntId) SetAuthKey(gasPrice, gasLimit uint64, payer *Account, ontId string,
	index, signIndex uint32, signer *Account) (common.Uint256, error) {
	tx, err := this.NewSetAuthKeyTransaction(gasPrice, gasLimit, ontId, index, signIndex)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	this.ontSdk.SetPayer(tx, payer.Address)
	err = this.ontSdk.SignToTransaction(tx, payer)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	err = this.ontSdk.SignToTransaction(tx, signer)
	if err != nil {
		return common.UINT256_EMPTY, err
	}

	return this.ontSdk.SendTransaction(tx)
}

func (this *OntId) NewSetAuthKeyByRecoveryTransaction(gasPrice, gasLimit uint64, ontId string, index uint32,
	signers []ontid.Signer) (*types.MutableTransaction, error) {
	s := ontid.SerializeSigners(signers)
	type AddNewAuthKeyByRecoveryParam struct {
		OntId   []byte
		Index   uint32
		Signers []byte
	}

	return this.native.NewNativeInvokeTransaction(
		gasPrice,
		gasLimit,
		ONT_ID_CONTRACT_VERSION,
		ONT_ID_CONTRACT_ADDRESS,
		"addNewAuthKeyByRecovery",
		[]interface{}{
			&AddNewAuthKeyByRecoveryParam{
				OntId:   []byte(ontId),
				Index:   index,
				Signers: s,
			},
		})
}

func (this *OntId) SetAuthKeyByRecovery(gasPrice, gasLimit uint64, payer *Account, ontId string,
	index uint32, signers []ontid.Signer, recoverySigners []*Account) (common.Uint256, error) {
	tx, err := this.NewSetAuthKeyByRecoveryTransaction(gasPrice, gasLimit, ontId, index, signers)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	this.ontSdk.SetPayer(tx, payer.Address)
	err = this.ontSdk.SignToTransaction(tx, payer)
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

func (this *OntId) NewSetAuthKeyByControllerTransaction(gasPrice, gasLimit uint64, ontId string, index uint32,
	signers []ontid.Signer) (*types.MutableTransaction, error) {
	s := ontid.SerializeSigners(signers)
	type AddNewAuthKeyByControllerParam struct {
		OntId   []byte
		Index   uint32
		Signers []byte
	}

	return this.native.NewNativeInvokeTransaction(
		gasPrice,
		gasLimit,
		ONT_ID_CONTRACT_VERSION,
		ONT_ID_CONTRACT_ADDRESS,
		"addNewAuthKeyByController",
		[]interface{}{
			&AddNewAuthKeyByControllerParam{
				OntId:   []byte(ontId),
				Index:   index,
				Signers: s,
			},
		})
}

func (this *OntId) SetAuthKeyByController(gasPrice, gasLimit uint64, payer *Account, ontId string,
	index uint32, signers []ontid.Signer, controllerSigners []*Account) (common.Uint256, error) {
	tx, err := this.NewSetAuthKeyByControllerTransaction(gasPrice, gasLimit, ontId, index, signers)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	this.ontSdk.SetPayer(tx, payer.Address)
	err = this.ontSdk.SignToTransaction(tx, payer)
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

func (this *OntId) NewRemoveAuthKeyTransaction(gasPrice, gasLimit uint64, ontId string, index uint32,
	signIndex uint32) (*types.MutableTransaction, error) {
	type RemoveAuthKeyParam struct {
		OntId     []byte
		Index     uint32
		SignIndex uint32
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
			},
		})
}

func (this *OntId) RemoveAuthKey(gasPrice, gasLimit uint64, payer *Account, ontId string, index uint32,
	signIndex uint32, signer *Account) (common.Uint256, error) {
	tx, err := this.NewRemoveAuthKeyTransaction(gasPrice, gasLimit, ontId, index, signIndex)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	this.ontSdk.SetPayer(tx, payer.Address)
	err = this.ontSdk.SignToTransaction(tx, payer)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	err = this.ontSdk.SignToTransaction(tx, signer)
	if err != nil {
		return common.UINT256_EMPTY, err
	}

	return this.ontSdk.SendTransaction(tx)
}

func (this *OntId) NewRemoveAuthKeyByRecoveryTransaction(gasPrice, gasLimit uint64, ontId string, index uint32,
	signers []ontid.Signer) (*types.MutableTransaction, error) {
	s := ontid.SerializeSigners(signers)
	type RemoveAuthKeyByRecoveryParam struct {
		OntId   []byte
		Index   uint32
		Signers []byte
	}

	return this.native.NewNativeInvokeTransaction(
		gasPrice,
		gasLimit,
		ONT_ID_CONTRACT_VERSION,
		ONT_ID_CONTRACT_ADDRESS,
		"removeAuthKeyByRecovery",
		[]interface{}{
			&RemoveAuthKeyByRecoveryParam{
				OntId:   []byte(ontId),
				Index:   index,
				Signers: s,
			},
		})
}

func (this *OntId) RemoveAuthKeyByRecovery(gasPrice, gasLimit uint64, payer *Account, ontId string, index uint32,
	signers []ontid.Signer, recoverySigners []*Account) (common.Uint256, error) {
	tx, err := this.NewRemoveAuthKeyByRecoveryTransaction(gasPrice, gasLimit, ontId, index, signers)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	this.ontSdk.SetPayer(tx, payer.Address)
	err = this.ontSdk.SignToTransaction(tx, payer)
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

func (this *OntId) NewRemoveAuthKeyByControllerTransaction(gasPrice, gasLimit uint64, ontId string, index uint32,
	signers []ontid.Signer) (*types.MutableTransaction, error) {
	s := ontid.SerializeSigners(signers)
	type RemoveAuthKeyByControllerParam struct {
		OntId   []byte
		Index   uint32
		Signers []byte
	}

	return this.native.NewNativeInvokeTransaction(
		gasPrice,
		gasLimit,
		ONT_ID_CONTRACT_VERSION,
		ONT_ID_CONTRACT_ADDRESS,
		"removeAuthKeyByController",
		[]interface{}{
			&RemoveAuthKeyByControllerParam{
				OntId:   []byte(ontId),
				Index:   index,
				Signers: s,
			},
		})
}

func (this *OntId) RemoveAuthKeyByController(gasPrice, gasLimit uint64, payer *Account, ontId string, index uint32,
	signers []ontid.Signer, controllerSigners []*Account) (common.Uint256, error) {
	tx, err := this.NewRemoveAuthKeyByControllerTransaction(gasPrice, gasLimit, ontId, index, signers)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	this.ontSdk.SetPayer(tx, payer.Address)
	err = this.ontSdk.SignToTransaction(tx, payer)
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

func (this *OntId) NewAddServiceTransaction(gasPrice, gasLimit uint64, ontId string, serviceId, type_, serviceEndpint []byte,
	index uint32) (*types.MutableTransaction, error) {
	type ServiceParam struct {
		OntId          []byte
		ServiceId      []byte
		Type           []byte
		ServiceEndpint []byte
		Index          uint32
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
			},
		})
}

func (this *OntId) AddService(gasPrice, gasLimit uint64, payer *Account, ontId string, serviceId, type_, serviceEndpint []byte,
	index uint32, signer *Account) (common.Uint256, error) {
	tx, err := this.NewAddServiceTransaction(gasPrice, gasLimit, ontId, serviceId, type_, serviceEndpint, index)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	this.ontSdk.SetPayer(tx, payer.Address)
	err = this.ontSdk.SignToTransaction(tx, payer)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	err = this.ontSdk.SignToTransaction(tx, signer)
	if err != nil {
		return common.UINT256_EMPTY, err
	}

	return this.ontSdk.SendTransaction(tx)
}

func (this *OntId) NewUpdateServiceTransaction(gasPrice, gasLimit uint64, ontId string, serviceId, type_, serviceEndpint []byte,
	index uint32) (*types.MutableTransaction, error) {
	type ServiceParam struct {
		OntId          []byte
		ServiceId      []byte
		Type           []byte
		ServiceEndpint []byte
		Index          uint32
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
			},
		})
}

func (this *OntId) UpdateService(gasPrice, gasLimit uint64, payer *Account, ontId string, serviceId, type_, serviceEndpint []byte,
	index uint32, signer *Account) (common.Uint256, error) {
	tx, err := this.NewUpdateServiceTransaction(gasPrice, gasLimit, ontId, serviceId, type_, serviceEndpint, index)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	this.ontSdk.SetPayer(tx, payer.Address)
	err = this.ontSdk.SignToTransaction(tx, payer)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	err = this.ontSdk.SignToTransaction(tx, signer)
	if err != nil {
		return common.UINT256_EMPTY, err
	}

	return this.ontSdk.SendTransaction(tx)
}

func (this *OntId) NewRemoveServiceTransaction(gasPrice, gasLimit uint64, ontId string, serviceId []byte, index uint32) (*types.MutableTransaction, error) {
	type ServiceRemoveParam struct {
		OntId     []byte
		ServiceId []byte
		Index     uint32
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
			},
		})
}

func (this *OntId) RemoveService(gasPrice, gasLimit uint64, payer *Account, ontId string, serviceId []byte, index uint32,
	signer *Account) (common.Uint256, error) {
	tx, err := this.NewRemoveServiceTransaction(gasPrice, gasLimit, ontId, serviceId, index)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	this.ontSdk.SetPayer(tx, payer.Address)
	err = this.ontSdk.SignToTransaction(tx, payer)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	err = this.ontSdk.SignToTransaction(tx, signer)
	if err != nil {
		return common.UINT256_EMPTY, err
	}

	return this.ontSdk.SendTransaction(tx)
}

func (this *OntId) NewAddContextTransaction(gasPrice, gasLimit uint64, ontId string, contexts [][]byte,
	index uint32) (*types.MutableTransaction, error) {
	type Context struct {
		OntId    []byte
		Contexts [][]byte
		Index    uint32
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
			},
		})
}

func (this *OntId) AddContext(gasPrice, gasLimit uint64, payer *Account, ontId string, contexts [][]byte,
	index uint32, signer *Account) (common.Uint256, error) {
	tx, err := this.NewAddContextTransaction(gasPrice, gasLimit, ontId, contexts, index)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	this.ontSdk.SetPayer(tx, payer.Address)
	err = this.ontSdk.SignToTransaction(tx, payer)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	err = this.ontSdk.SignToTransaction(tx, signer)
	if err != nil {
		return common.UINT256_EMPTY, err
	}

	return this.ontSdk.SendTransaction(tx)
}

func (this *OntId) NewRemoveContextTransaction(gasPrice, gasLimit uint64, ontId string, contexts [][]byte,
	index uint32) (*types.MutableTransaction, error) {
	type Context struct {
		OntId    []byte
		Contexts [][]byte
		Index    uint32
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
			},
		})
}

func (this *OntId) RemoveContext(gasPrice, gasLimit uint64, payer *Account, ontId string, contexts [][]byte,
	index uint32, signer *Account) (common.Uint256, error) {
	tx, err := this.NewRemoveContextTransaction(gasPrice, gasLimit, ontId, contexts, index)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	this.ontSdk.SetPayer(tx, payer.Address)
	err = this.ontSdk.SignToTransaction(tx, payer)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	err = this.ontSdk.SignToTransaction(tx, signer)
	if err != nil {
		return common.UINT256_EMPTY, err
	}

	return this.ontSdk.SendTransaction(tx)
}

func (this *OntId) VerifySignature(ontId string, keyIndex uint64, account *Account) (bool, error) {
	type verifySignatureParam struct {
		OntId    string
		KeyIndex uint64
	}
	tx, err := this.native.NewNativeInvokeTransaction(
		0, 0,
		ONT_ID_CONTRACT_VERSION,
		ONT_ID_CONTRACT_ADDRESS,
		"verifySignature",
		[]interface{}{
			verifySignatureParam{
				ontId,
				keyIndex,
			},
		})
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

func (this *OntId) VerifyController(ontId string, signers []ontid.Signer, accounts []*Account) (bool, error) {
	type verifyControllerParam struct {
		OntId   string
		Signers []byte
	}
	s := ontid.SerializeSigners(signers)
	tx, err := this.native.NewNativeInvokeTransaction(
		0, 0,
		ONT_ID_CONTRACT_VERSION,
		ONT_ID_CONTRACT_ADDRESS,
		"verifyController",
		[]interface{}{
			verifyControllerParam{
				ontId,
				s,
			},
		})
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

func (this *OntId) GetPublicKeysJson(ontId string) ([]byte, error) {
	preResult, err := this.native.PreExecInvokeNativeContract(
		ONT_ID_CONTRACT_ADDRESS,
		ONT_ID_CONTRACT_VERSION,
		"getPublicKeysJson",
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

func (this *OntId) GetAttributesJson(ontId string) ([]byte, error) {
	preResult, err := this.native.PreExecInvokeNativeContract(
		ONT_ID_CONTRACT_ADDRESS,
		ONT_ID_CONTRACT_VERSION,
		"getAttributesJson",
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

func (this *OntId) GetAttributes(ontId string) ([]byte, error) {
	preResult, err := this.native.PreExecInvokeNativeContract(
		ONT_ID_CONTRACT_ADDRESS,
		ONT_ID_CONTRACT_VERSION,
		"getAttributes",
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

func (this *OntId) GetAttributeByKey(ontId, key string) ([]byte, error) {
	type getAttributeByKeyParam struct {
		OntId string
		Key   string
	}
	preResult, err := this.native.PreExecInvokeNativeContract(
		ONT_ID_CONTRACT_ADDRESS,
		ONT_ID_CONTRACT_VERSION,
		"getAttributeByKey",
		[]interface{}{
			getAttributeByKeyParam{
				ontId,
				key,
			},
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

func (this *OntId) GetServiceJson(ontId string, serviceId string) ([]byte, error) {
	type getServiceJsonParam struct {
		OntId     string
		ServiceId string
	}
	preResult, err := this.native.PreExecInvokeNativeContract(
		ONT_ID_CONTRACT_ADDRESS,
		ONT_ID_CONTRACT_VERSION,
		"getServiceJson",
		[]interface{}{
			getServiceJsonParam{
				ontId,
				serviceId,
			},
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

func (this *OntId) GetControllerJson(ontId string) ([]byte, error) {
	preResult, err := this.native.PreExecInvokeNativeContract(
		ONT_ID_CONTRACT_ADDRESS,
		ONT_ID_CONTRACT_VERSION,
		"getControllerJson",
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

func (this *OntId) GetDocumentJson(ontId string) ([]byte, error) {
	preResult, err := this.native.PreExecInvokeNativeContract(
		ONT_ID_CONTRACT_ADDRESS,
		ONT_ID_CONTRACT_VERSION,
		"getDocumentJson",
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
func (this *OntId) GetDDO(ontId string) ([]byte, error) {
	preResult, err := this.native.PreExecInvokeNativeContract(
		ONT_ID_CONTRACT_ADDRESS,
		ONT_ID_CONTRACT_VERSION,
		"getDDO",
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
