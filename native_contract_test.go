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
	"testing"
	"time"
)

func TestOntId(t *testing.T) {
	Init()
	testIdentity, err := testWallet.NewDefaultSettingIdentity(testPasswd)
	if err != nil {
		t.Errorf("TestOntId NewDefaultSettingIdentity error:%s", err)
		return
	}
	_, err = testOntSdk.Native.OntId.RegIDWithPublicKey(testGasPrice, testGasLimit, testDefAcc, testIdentity.ID, testDefAcc)
	if err != nil {
		t.Errorf("TestOntId RegIDWithPublicKey error:%s", err)
		return
	}
	testOntSdk.WaitForGenerateBlock(30 * time.Second)
	attributes := []*DDOAttribute{
		&DDOAttribute{
			Key:       []byte("1"),
			Value:     []byte("2"),
			ValueType: []byte("3"),
		},
	}
	_, err = testOntSdk.Native.OntId.AddAttributesByIndex(testGasPrice, testGasLimit, testDefAcc, testIdentity.ID, attributes, 1, testDefAcc)
	if err != nil {
		t.Errorf("TestOntId AddAttributesByIndex error:%s", err)
		return
	}
	testOntSdk.WaitForGenerateBlock(30 * time.Second)
	attribute, err := testOntSdk.Native.OntId.GetAttributeByKey(testIdentity.ID, "1")
	if err != nil {
		t.Errorf("TestOntId GetAttributeByKey error:%s", err)
		return
	}
	fmt.Printf("TestOntId GetAttributeByKey:%+v\n", attribute)
	document, err := testOntSdk.Native.OntId.GetDocumentJson(testIdentity.ID)
	if err != nil {
		t.Errorf("TestOntId GetDocumentJson error:%s", err)
		return
	}
	fmt.Printf("TestOntId GetDocumentJson:%+v\n", string(document))
	return
}
