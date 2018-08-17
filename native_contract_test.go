package ontology_go_sdk

import (
	"encoding/hex"
	"fmt"
	"github.com/ontio/ontology-crypto/keypair"
	"testing"
	"time"
)

func TestOntId_RegIDWithPublicKey(t *testing.T) {
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
	txHash, err := testOntSdk.Native.OntId.RegIDWithPublicKey(testGasPrice, testGasLimit, testDefAcc, testIdentity.ID, testDefController)
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

	ddo, err := testOntSdk.Native.OntId.GetDDO(testIdentity.ID)
	if err != nil {
		t.Errorf("TestOntId_RegIDWithPublicKey GetDDO error:%s", err)
		return
	}
	fmt.Printf("TestOntId_RegIDWithPublicKey DDO:%+v\n", ddo)
}

func TestOntId_RegIDWithAttributes(t *testing.T) {
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
	_, err = testOntSdk.Native.OntId.RegIDWithAttributes(testGasPrice, testGasLimit, testDefAcc, testIdentity.ID, testDefController, attributes)
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
	_, err = testOntSdk.Native.OntId.RegIDWithPublicKey(testGasPrice, testGasLimit, testDefAcc, testIdentity.ID, testDefController)
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

	_, err = testOntSdk.Native.OntId.AddKey(testGasPrice, testGasLimit, testIdentity.ID, testDefAcc, controller1.PublicKey, testDefController)
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

	_, err = testOntSdk.Native.OntId.RevokeKey(testGasPrice, testGasLimit, testIdentity.ID, testDefAcc, testDefController.PublicKey, controller1)
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
	_, err = testOntSdk.Native.OntId.RegIDWithPublicKey(testGasPrice, testGasLimit, testDefAcc, testIdentity.ID, testDefController)
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
	_, err = testOntSdk.Native.OntId.AddAttributes(testGasPrice, testGasLimit, testDefAcc, testIdentity.ID, attributes, testDefController)
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
	if string(attr1.Key) != string(attrs[0].Key) || string(attr1.Value) != string(attrs[0].Value) || string(attr1.ValueType) != string(attrs[0].ValueType) {
		t.Errorf("TestOntId_Attribute attribute:%s != %s", attrs[0], attr1)
		return
	}

	_, err = testOntSdk.Native.OntId.RemoveAttribute(testGasPrice, testGasLimit, testDefAcc, testIdentity.ID, attr1.Key, testDefController)
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
	_, err = testOntSdk.Native.OntId.RegIDWithPublicKey(testGasPrice, testGasLimit, testDefAcc, testIdentity.ID, testDefController)
	if err != nil {
		t.Errorf("TestOntId_Recovery RegIDWithPublicKey error:%s", err)
		return
	}
	testOntSdk.WaitForGenerateBlock(30*time.Second, 1)
	_, err = testOntSdk.Native.OntId.SetRecovery(testGasPrice, testGasLimit, testDefAcc, testIdentity.ID, testDefAcc.Address, testDefController)
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

	txHash, err := testOntSdk.Native.OntId.SetRecovery(testGasPrice, testGasLimit, testDefAcc, testIdentity.ID, acc1.Address, testDefController)

	testOntSdk.WaitForGenerateBlock(30*time.Second, 1)
	evt, err := testOntSdk.GetSmartContractEvent(txHash.ToHexString())
	if err != nil {
		t.Errorf("TestOntId_Recovery GetSmartContractEvent:%s error:%s", txHash.ToHexString(), err)
		return
	}
	if evt.State == 1 {
		t.Errorf("TestOntId_Recovery duplicate add recovery should failed")
		return
	}
	_, err = testOntSdk.Native.OntId.ChangeRecovery(testGasPrice, testGasLimit, testDefAcc, testIdentity.ID, acc1.Address, testDefAcc.Address, testDefController)
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
