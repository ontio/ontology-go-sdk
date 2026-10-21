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
	"testing"

	"github.com/ontio/ontology-crypto/keypair"
	"github.com/ontio/ontology/common"
	"github.com/ontio/ontology/core/types"
	"github.com/ontio/ontology/core/validation"
	ontErrors "github.com/ontio/ontology/errors"
	"github.com/stretchr/testify/assert"
)

func TestSetTransactionSigners(t *testing.T) {
	sdk := NewOntologySdk()
	payer := NewAccount()
	first := NewAccount()
	second := NewAccount()

	tx, err := sdk.Native.Ont.NewTransferTransaction(0, 0, first.Address, second.Address, 1)
	assert.Nil(t, err)
	sdk.SetPayer(tx, payer.Address)

	err = sdk.SetSignerAddresses(tx, payer.Address, first.Address, second.Address, first.Address)
	assert.Nil(t, err)
	assert.Equal(t, []common.Address{first.Address, second.Address}, tx.ExtraSigners)

	immutable, err := tx.IntoImmutable()
	assert.Nil(t, err)
	assert.Equal(t, []common.Address{first.Address, second.Address}, immutable.ExtraSigners)
}

func TestSignWithPayerPopulatesExtraSigners(t *testing.T) {
	sdk := NewOntologySdk()
	payer := NewAccount()
	signer := NewAccount()

	tx, err := sdk.Native.Ont.NewTransferTransaction(0, 0, signer.Address, payer.Address, 1)
	assert.Nil(t, err)
	assert.Nil(t, sdk.SignAllToTransaction(tx, payer, signer))
	assert.Equal(t, payer.Address, tx.Payer)
	assert.Equal(t, []common.Address{signer.Address}, tx.ExtraSigners)
	assert.Len(t, tx.Sigs, 2)

	immutable, err := tx.IntoImmutable()
	assert.Nil(t, err)
	assert.Equal(t, ontErrors.ErrNoError, validation.VerifyTransaction(immutable, true))
}

func TestSignToTransactionRejectsUndeclaredSignerAfterSigning(t *testing.T) {
	sdk := NewOntologySdk()
	payer := NewAccount()
	signer := NewAccount()

	tx, err := sdk.Native.Ont.NewTransferTransaction(0, 0, signer.Address, payer.Address, 1)
	assert.Nil(t, err)
	sdk.SetPayer(tx, payer.Address)

	assert.Nil(t, sdk.SignToTransaction(tx, payer))
	assert.NotNil(t, sdk.SignToTransaction(tx, signer))
}

func TestMultiSignTransactionKeepsExtraSignersEmpty(t *testing.T) {
	sdk := NewOntologySdk()
	first := NewAccount()
	second := NewAccount()
	pubKeys := []keypair.PublicKey{first.PublicKey, second.PublicKey}
	multiAddr, err := types.AddressFromMultiPubKeys(pubKeys, 2)
	assert.Nil(t, err)

	tx, err := sdk.Native.Ont.NewTransferTransaction(0, 0, multiAddr, first.Address, 1)
	assert.Nil(t, err)
	assert.Nil(t, sdk.MultiSignToTransaction(tx, 2, pubKeys, first))
	assert.Nil(t, sdk.MultiSignToTransaction(tx, 2, pubKeys, second))
	assert.Empty(t, tx.ExtraSigners)
	assert.Equal(t, multiAddr, tx.Payer)

	immutable, err := tx.IntoImmutable()
	assert.Nil(t, err)
	assert.Equal(t, ontErrors.ErrNoError, validation.VerifyTransaction(immutable, true))
}
