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
	"encoding/hex"
	"fmt"
	"github.com/ontio/ontology-crypto/keypair"
	"github.com/stretchr/testify/assert"
	"testing"
	"time"
)

func TestOntId_RegIDWithPublicKey(t *testing.T) {
	return
	Init()
	testIdentity, err := testWallet.NewDefaultSettingIdentity(testPasswd)
	if err != nil {
		t.Errorf("TestOntId_RegIDWithPublicKey NewDefaultSettingIdentity error:%s", err)
		return
	}
	testDefController, err := testIdentity.GetControllerByIndex(1, testPasswd)
	if err != nil {
		t.Errorf("TestOntId_RegIDWithPublicKey GetControllerByIndex error:%s", err)
		return
	}
	txHash, err := testOntSdk.Native.OntId.RegIDWithPublicKey(testGasPrice, testGasLimit, nil, testDefAcc, testIdentity.ID, testDefController)
	if err != nil {
		t.Errorf("TestOntId_RegIDWithPublicKey RegIDWithPublicKey error:%s", err)
		return
	}
	testOntSdk.WaitForGenerateBlock(30*time.Second, 1)
	event, err := testOntSdk.GetSmartContractEvent(txHash.ToHexString())
	if err != nil {
		t.Errorf("TestOntId_RegIDWithPublicKey GetSmartContractEvent error:%s", err)
		return
	}
	fmt.Printf("TestOntId_RegIDWithPublicKey Event: %+v\n", event)
	fmt.Println("testIdentity.ID:", testIdentity.ID)
	ddo, err := testOntSdk.Native.OntId.GetDDO(testIdentity.ID)
	if err != nil {
		t.Errorf("TestOntId_RegIDWithPublicKey GetDDO error:%s", err)
		return
	}
	fmt.Printf("TestOntId_RegIDWithPublicKey DDO:%+v\n", ddo)
}

func TestOntId_RegIDWithAttributes(t *testing.T) {
	return
	testIdentity, err := testWallet.NewDefaultSettingIdentity(testPasswd)
	if err != nil {
		t.Errorf("TestOntId_RegIDWithPublicKey NewDefaultSettingIdentity error:%s", err)
		return
	}
	testDefController, err := testIdentity.GetControllerByIndex(1, testPasswd)
	if err != nil {
		t.Errorf("TestOntId_RegIDWithPublicKey GetControllerByIndex error:%s", err)
		return
	}
	attributes := make([]*DDOAttribute, 0)
	attr1 := &DDOAttribute{
		Key:       []byte("Hello"),
		Value:     []byte("World"),
		ValueType: []byte("string"),
	}
	attributes = append(attributes, attr1)
	attr2 := &DDOAttribute{
		Key:       []byte("Foo"),
		Value:     []byte("Bar"),
		ValueType: []byte("string"),
	}
	attributes = append(attributes, attr2)
	_, err = testOntSdk.Native.OntId.RegIDWithAttributes(testGasPrice, testGasLimit, nil, testDefAcc, testIdentity.ID, testDefController, attributes)
	if err != nil {
		t.Errorf("TestOntId_RegIDWithPublicKey RegIDWithAttributes error:%s", err)
		return
	}
	testOntSdk.WaitForGenerateBlock(30*time.Second, 1)

	ddo, err := testOntSdk.Native.OntId.GetDDO(testIdentity.ID)
	if err != nil {
		t.Errorf("GetDDO error:%s", err)
		return
	}

	owners := ddo.Owners
	if owners[0].Value != hex.EncodeToString(keypair.SerializePublicKey(testDefController.GetPublicKey())) {
		t.Errorf("TestOntId_RegIDWithPublicKey pubkey %s != %s", owners[0].Value, hex.EncodeToString(keypair.SerializePublicKey(testDefController.GetPublicKey())))
		return
	}
	attrs := ddo.Attributes
	if len(attributes) != len(attrs) {
		t.Errorf("TestOntId_RegIDWithPublicKey attribute size %d != %d", len(attrs), len(attributes))
		return
	}
	fmt.Printf("Owner:%+v\n", owners[0])
	if string(attr1.Key) != string(attrs[0].Key) ||
		string(attr1.Value) != string(attrs[0].Value) ||
		string(attr1.ValueType) != string(attrs[0].ValueType) {
		t.Errorf("TestOntId_RegIDWithPublicKey Attribute %s != %s", attrs[0], attr1)
	}
	if string(attr2.Key) != string(attrs[1].Key) ||
		string(attr2.Value) != string(attrs[1].Value) ||
		string(attr2.ValueType) != string(attrs[1].ValueType) {
		t.Errorf("TestOntId_RegIDWithPublicKey Attribute %s != %s", attrs[1], attr2)
	}
}

func TestOntId_Key(t *testing.T) {
	return
	testIdentity, err := testWallet.NewDefaultSettingIdentity(testPasswd)
	if err != nil {
		t.Errorf("TestOntId_Key NewDefaultSettingIdentity error:%s", err)
		return
	}
	testDefController, err := testIdentity.GetControllerByIndex(1, testPasswd)
	if err != nil {
		t.Errorf("TestOntId_Key GetControllerByIndex error:%s", err)
		return
	}
	_, err = testOntSdk.Native.OntId.RegIDWithPublicKey(testGasPrice, testGasLimit, nil, testDefAcc, testIdentity.ID, testDefController)
	if err != nil {
		t.Errorf("TestOntId_Key RegIDWithPublicKey error:%s", err)
		return
	}
	testOntSdk.WaitForGenerateBlock(30*time.Second, 1)

	controller1, err := testIdentity.NewDefaultSettingController("2", testPasswd)
	if err != nil {
		t.Errorf("TestOntId_Key NewDefaultSettingController error:%s", err)
		return
	}

	_, err = testOntSdk.Native.OntId.AddKey(testGasPrice, testGasLimit, nil, testIdentity.ID, testDefAcc, controller1.PublicKey, testDefController)
	if err != nil {
		t.Errorf("TestOntId_Key AddKey error:%s", err)
		return
	}
	testOntSdk.WaitForGenerateBlock(30*time.Second, 1)

	owners, err := testOntSdk.Native.OntId.GetPublicKeys(testIdentity.ID)
	if err != nil {
		t.Errorf("TestOntId_Key GetPublicKeys error:%s", err)
		return
	}

	if len(owners) != 2 {
		t.Errorf("TestOntId_Key owner size:%d != 2", len(owners))
		return
	}

	if owners[0].Value != hex.EncodeToString(keypair.SerializePublicKey(testDefController.PublicKey)) {
		t.Errorf("TestOntId_Key owner index:%d pubkey:%s != %s", owners[0].pubKeyIndex, owners[0].Value, hex.EncodeToString(keypair.SerializePublicKey(testDefController.PublicKey)))
		return
	}

	if owners[1].Value != hex.EncodeToString(keypair.SerializePublicKey(controller1.PublicKey)) {
		t.Errorf("TestOntId_Key owner index:%d pubkey:%s != %s", owners[1].pubKeyIndex, owners[1].Value, hex.EncodeToString(keypair.SerializePublicKey(controller1.PublicKey)))
		return
	}

	_, err = testOntSdk.Native.OntId.RevokeKey(testGasPrice, testGasLimit, nil, testIdentity.ID, testDefAcc, testDefController.PublicKey, controller1)
	if err != nil {
		t.Errorf("TestOntId_Key RevokeKey error:%s", err)
		return
	}
	testOntSdk.WaitForGenerateBlock(30*time.Second, 1)

	owners, err = testOntSdk.Native.OntId.GetPublicKeys(testIdentity.ID)
	if err != nil {
		t.Errorf("TestOntId_Key GetPublicKeys error:%s", err)
		return
	}

	if len(owners) != 1 {
		t.Errorf("TestOntId_Key owner size:%d != 1 after remove", len(owners))
		return
	}

	state, err := testOntSdk.Native.OntId.GetKeyState(testIdentity.ID, 1)
	if err != nil {
		t.Errorf("TestOntId_Key GetKeyState error:%s", err)
		return
	}

	if state != KEY_STATUS_REVOKE {
		t.Errorf("TestOntId_Key remove key state != %s", KEY_STATUS_REVOKE)
		return
	}

	state, err = testOntSdk.Native.OntId.GetKeyState(testIdentity.ID, 2)
	if err != nil {
		t.Errorf("TestOntId_Key GetKeyState error:%s", err)
		return
	}
	if state != KEY_STSTUS_IN_USE {
		t.Errorf("TestOntId_Key GetKeyState state != %s", KEY_STSTUS_IN_USE)
		return
	}
}

func TestOntId_Attribute(t *testing.T) {
	return
	Init()
	testIdentity, err := testWallet.NewDefaultSettingIdentity(testPasswd)
	if err != nil {
		t.Errorf("TestOntId_Attribute NewDefaultSettingIdentity error:%s", err)
		return
	}
	testDefController, err := testIdentity.GetControllerByIndex(1, testPasswd)
	if err != nil {
		t.Errorf("TestOntId_Attribute GetControllerByIndex error:%s", err)
		return
	}
	_, err = testOntSdk.Native.OntId.RegIDWithPublicKey(testGasPrice, testGasLimit, nil, testDefAcc, testIdentity.ID, testDefController)
	if err != nil {
		t.Errorf("TestOntId_Attribute RegIDWithPublicKey error:%s", err)
		return
	}
	testOntSdk.WaitForGenerateBlock(30*time.Second, 1)

	attributes := make([]*DDOAttribute, 0)
	attr1 := &DDOAttribute{
		Key:       []byte("Foo"),
		Value:     []byte("Bar"),
		ValueType: []byte("string"),
	}
	attributes = append(attributes, attr1)
	attr2 := &DDOAttribute{
		Key:       []byte("Hello"),
		Value:     []byte("World"),
		ValueType: []byte("string"),
	}
	attributes = append(attributes, attr2)
	_, err = testOntSdk.Native.OntId.AddAttributes(testGasPrice, testGasLimit, nil, testDefAcc, testIdentity.ID, attributes, testDefController)
	if err != nil {
		t.Errorf("TestOntId_Attribute AddAttributes error:%s", err)
		return
	}
	testOntSdk.WaitForGenerateBlock(30*time.Second, 1)
	attrs, err := testOntSdk.Native.OntId.GetAttributes(testIdentity.ID)
	if len(attributes) != len(attrs) {
		t.Errorf("TestOntId_Attribute GetAttributes len:%d != %d", len(attrs), len(attributes))
		return
	}
	fmt.Println("attrs:", attrs)
	if string(attr1.Key) != string(attrs[0].Key) || string(attr1.Value) != string(attrs[0].Value) || string(attr1.ValueType) != string(attrs[0].ValueType) {
		t.Errorf("TestOntId_Attribute attribute:%s != %s", attrs[0], attr1)
		return
	}

	_, err = testOntSdk.Native.OntId.RemoveAttribute(testGasPrice, testGasLimit, nil, testDefAcc, testIdentity.ID, attr1.Key, testDefController)
	if err != nil {
		t.Errorf("TestOntId_Attribute RemoveAttribute error:%s", err)
		return
	}
	testOntSdk.WaitForGenerateBlock(30*time.Second, 1)
	attrs, err = testOntSdk.Native.OntId.GetAttributes(testIdentity.ID)
	if len(attrs) != 1 {
		t.Errorf("TestOntId_Attribute GetAttributes len:%d != 1", len(attrs))
		return
	}
	if string(attr2.Key) != string(attrs[0].Key) || string(attr2.Value) != string(attrs[0].Value) || string(attr2.ValueType) != string(attrs[0].ValueType) {
		t.Errorf("TestOntId_Attribute attribute:%s != %s", attrs[0], attr2)
		return
	}
}

func TestOntId_Recovery(t *testing.T) {
	return
	testIdentity, err := testWallet.NewDefaultSettingIdentity(testPasswd)
	if err != nil {
		t.Errorf("TestOntId_Recovery NewDefaultSettingIdentity error:%s", err)
		return
	}
	testDefController, err := testIdentity.GetControllerByIndex(1, testPasswd)
	if err != nil {
		t.Errorf("TestOntId_Recovery GetControllerByIndex error:%s", err)
		return
	}
	_, err = testOntSdk.Native.OntId.RegIDWithPublicKey(testGasPrice, testGasLimit, nil, testDefAcc, testIdentity.ID, testDefController)
	if err != nil {
		t.Errorf("TestOntId_Recovery RegIDWithPublicKey error:%s", err)
		return
	}
	testOntSdk.WaitForGenerateBlock(30*time.Second, 1)
	_, err = testOntSdk.Native.OntId.SetRecovery(testGasPrice, testGasLimit, nil, testDefAcc, testIdentity.ID, testDefAcc.Address, testDefController)
	if err != nil {
		t.Errorf("TestOntId_Recovery SetRecovery error:%s", err)
		return
	}
	testOntSdk.WaitForGenerateBlock(30*time.Second, 1)
	ddo, err := testOntSdk.Native.OntId.GetDDO(testIdentity.ID)
	if err != nil {
		t.Errorf("TestOntId_Recovery GetDDO error:%s", err)
		return
	}
	if ddo.Recovery != testDefAcc.Address.ToBase58() {
		t.Errorf("TestOntId_Recovery recovery address:%s != %s", ddo.Recovery, testDefAcc.Address.ToBase58())
		return
	}

	acc1, err := testWallet.NewDefaultSettingAccount(testPasswd)
	if err != nil {
		t.Errorf("TestOntId_Recovery NewDefaultSettingAccount error:%s", err)
		return
	}

	txHash, err := testOntSdk.Native.OntId.SetRecovery(testGasPrice, testGasLimit, nil, testDefAcc, testIdentity.ID, acc1.Address, testDefController)

	testOntSdk.WaitForGenerateBlock(30*time.Second, 1)
	evt, err := testOntSdk.GetSmartContractEvent(txHash.ToHexString())
	if err != nil {
		t.Errorf("TestOntId_Recovery GetSmartContractEvent:%s error:%s", txHash.ToHexString(), err)
		return
	}

	if evt != nil && evt.State == 1 {
		t.Errorf("TestOntId_Recovery duplicate add recovery should failed")
		return
	}
	_, err = testOntSdk.Native.OntId.ChangeRecovery(testGasPrice, testGasLimit, nil, testDefAcc, testIdentity.ID, acc1.Address, testDefAcc.Address, testDefController)
	if err != nil {
		t.Errorf("TestOntId_Recovery ChangeRecovery error:%s", err)
		return
	}
	testOntSdk.WaitForGenerateBlock(30*time.Second, 1)
	ddo, err = testOntSdk.Native.OntId.GetDDO(testIdentity.ID)
	if err != nil {
		t.Errorf("TestOntId_Recovery GetDDO error:%s", err)
		return
	}
	if ddo.Recovery != acc1.Address.ToBase58() {
		t.Errorf("TestOntId_Recovery recovery address:%s != %s", ddo.Recovery, acc1.Address.ToBase58())
		return
	}
}

func TestOntId_CreateOntIdClaim(t *testing.T) {
	testIdentity, err := testWallet.NewDefaultSettingIdentity(testPasswd)
	assert.Nil(t, err)
	testIdentity2, err := testWallet.NewDefaultSettingIdentity(testPasswd)
	assert.Nil(t, err)
	payer, err := testWallet.NewDefaultSettingAccount(testPasswd)
	assert.Nil(t, err)

	testOntSdk.NewRpcClient().SetAddress("http://127.0.0.1:20336")

	controller, err := testIdentity.controllers[0].GetController(testPasswd)
	_, err = testOntSdk.Native.OntId.RegIDWithPublicKey(0, 20000, payer, payer, testIdentity.ID, controller)
	controller2, err := testIdentity2.controllers[0].GetController(testPasswd)
	_, err = testOntSdk.Native.OntId.RegIDWithPublicKey(0, 20000, payer, payer, testIdentity.ID, controller2)
	assert.Nil(t, err)
	time.Sleep(6 * time.Second)
	ddo, err := testOntSdk.Native.OntId.GetDDO(testIdentity.ID)
	assert.NotNil(t, ddo)
	assert.Nil(t, err)
	ddo, err = testOntSdk.Native.OntId.GetDDO(testIdentity.ID)
	assert.Nil(t, err)
	assert.NotNil(t, ddo)
	metaData := map[string]string{
		"Issuer":  testIdentity.ID,
		"Subject": testIdentity2.ID,
	}
	clmRevMap := map[string]interface{}{
		"typ":  "AttestContract",
		"addr": testIdentity.ID,
	}
	claim, err := testOntSdk.Native.OntId.CreateOntIdClaim(controller, "claim:context", metaData, clmRevMap, clmRevMap, time.Now().Unix()+1000)
	assert.Nil(t, err)
	boo, err := testOntSdk.Native.OntId.VerifyOntIdClaim(claim)
	assert.Nil(t, err)
	assert.True(t, boo)
	fmt.Println("claim:", claim)
}

func TestOntId_VerifyOntIdClaim(t *testing.T) {
	testOntSdk.NewRpcClient().SetAddress("http://127.0.0.1:20336")
	//generate by java-sdk
	claimStr := "eyJraWQiOiJkaWQ6b250OkFTejlOZENCVUdEclpZVGhuY2hGZkp0ZVFWcnUyUDNtcXEja2V5cy0xIiwidHlwIjoiSldULVgiLCJhbGciOiJPTlQtRVMyNTYifQ==.eyJjbG0tcmV2Ijp7Iklzc3VlciI6ImRpZDpvbnQ6QVN6OU5kQ0JVR0RyWllUaG5jaEZmSnRlUVZydTJQM21xcSIsIlN1YmplY3QiOiJkaWQ6b250OkFhcnJNQnkxaUdKU1o1VG1VUUNvak55VlZUdWdpUExQaWsifSwic3ViIjoiZGlkOm9udDpBYXJyTUJ5MWlHSlNaNVRtVVFDb2pOeVZWVHVnaVBMUGlrIiwidmVyIjoidjEuMCIsImNsbSI6eyIkcmVmIjoiJC5jbG0tcmV2In0sImlzcyI6ImRpZDpvbnQ6QVN6OU5kQ0JVR0RyWllUaG5jaEZmSnRlUVZydTJQM21xcSIsImV4cCI6MTU4NjQ5OTEwNCwiaWF0IjoxNTg2NDk4MTA1LCJAY29udGV4dCI6ImNsYWltOmNvbnRleHQiLCJqdGkiOiI1MzlhMzlmNWYyY2E1NzRlNTdkMjY2NzRiMDBhZTc5ZTBkODdiYjExMTNmODBlZWNmZDFkZDhjNThhOTNiM2NjIn0=.AZ1jo4XYus7+ovFK5FKr3l5GxJihfDUPlsiOhY4vyiRf283L8AYG7fIguE2HLUEDLIE7rGxc6jnU8/ts77MLo6U="
	res, err := testOntSdk.Native.OntId.VerifyOntIdClaim(claimStr)
	assert.Nil(t, err)
	assert.True(t, res)
}
