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

	"fmt"
	"github.com/stretchr/testify/assert"
	"time"
)

func TestNewClaim(t *testing.T) {
	wallet := NewWallet("./wallet.dat")
	pwd := []byte("111111")
	acct, err := wallet.NewDefaultSettingIdentity(pwd)
	assert.Nil(t, err)
	clmMap := map[string]interface{}{
		"1111": "1111",
	}
	metadata := map[string]string{
		"2222": "2222",
	}
	clmRevMap := map[string]interface{}{
		"333": "333",
	}
	con, err := acct.controllers[0].GetController(pwd)
	assert.Nil(t, err)
	claim, err := NewClaim(con, "", clmMap, metadata, clmRevMap, "", time.Now().Unix()+20)
	assert.Nil(t, err)
	fmt.Println(claim.claimStr)
}
