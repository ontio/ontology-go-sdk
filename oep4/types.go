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
package oep4

import (
	"fmt"
	"math/big"

	"github.com/ontio/ontology/common"
)

type State struct {
	From   common.Address
	To     common.Address
	Amount *big.Int
}

type Oep4TransferEvent struct {
	Name   string
	From   common.Address
	To     common.Address
	Amount *big.Int
}

func (this *Oep4TransferEvent) String() string {
	return fmt.Sprintf("name %s, from %s, to %s, amount %s", this.Name, this.From.ToBase58(), this.To.ToBase58(),
		this.Amount.String())
}
