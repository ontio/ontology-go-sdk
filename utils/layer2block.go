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

package utils

import (
	"errors"
	"io"

	"github.com/ontio/ontology/common"
	"github.com/ontio/ontology/core/types"
)

type Layer2Block struct {
	Header       *Layer2Header
	Transactions []*types.Transaction
}

// if no error, ownership of param raw is transfered to Transaction
func Layer2BlockFromRawBytes(raw []byte) (*Layer2Block, error) {
	source := common.NewZeroCopySource(raw)
	block := &Layer2Block{}
	err := block.Deserialization(source)
	if err != nil {
		return nil, err
	}
	return block, nil
}

func (self *Layer2Block) Deserialization(source *common.ZeroCopySource) error {
	if self.Header == nil {
		self.Header = new(Layer2Header)
	}
	err := self.Header.Deserialization(source)
	if err != nil {
		return err
	}

	length, eof := source.NextUint32()
	if eof {
		return io.ErrUnexpectedEOF
	}

	var hashes []common.Uint256
	mask := make(map[common.Uint256]bool)
	for i := uint32(0); i < length; i++ {
		transaction := new(types.Transaction)
		// note currently all transaction in the block shared the same source
		err := transaction.Deserialization(source)
		if err != nil {
			return err
		}
		txhash := transaction.Hash()
		if mask[txhash] {
			return errors.New("duplicated transaction in block")
		}
		mask[txhash] = true
		hashes = append(hashes, txhash)
		self.Transactions = append(self.Transactions, transaction)
	}

	root := common.ComputeMerkleRoot(hashes)
	if self.Header.TransactionsRoot != root {
		return errors.New("mismatched transaction root")
	}

	return nil
}
