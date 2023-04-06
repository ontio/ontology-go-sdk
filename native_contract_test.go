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
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/ontio/ontology/common"
	"github.com/stretchr/testify/assert"
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

func TestGovReadData(t *testing.T) {
	testNetUrl = "http://172.16.8.254:20336"
	Init()
	view, err := testOntSdk.Native.Governance.GetCurrentView()
	assert.Nil(t, err)
	t.Logf("current view: %d", view)
	// consensus node, okex pool
	user, err := common.AddressFromBase58("APBX1duPLaQ3ikmMCZixjmNi2B73ARq3w6")
	assert.Nil(t, err)
	authorizeInfo, err := testOntSdk.Native.Governance.GetAuthorizeInfo(user, "039cadf7145731b3c868bd3528da9172757f89b566fc0372cd51b41351c3b6f237")
	assert.Nil(t, err)
	data, _ := json.MarshalIndent(authorizeInfo, "", "	")
	t.Log(string(data))
	fee, err := testOntSdk.Native.Governance.GetAddressFee(user)
	assert.Nil(t, err)
	t.Logf("fee: %d", fee)
	// candidate node, BeRich
	user, _ = common.AddressFromBase58("AHHSvf3Zn2zAhamkYRRYiXa4Ko5GNUrQjv")
	authorizeInfo, err = testOntSdk.Native.Governance.GetAuthorizeInfo(user, "03446c4703bb907091eff15def2e1ead72772b70f187d0a0a237ae7d28c196f644")
	assert.Nil(t, err)
	data, _ = json.MarshalIndent(authorizeInfo, "", "	")
	t.Log(string(data))
	fee, err = testOntSdk.Native.Governance.GetAddressFee(user)
	assert.Nil(t, err)
	t.Logf("fee: %d", fee)
}
