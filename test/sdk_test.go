package test

import (
	"github.com/ontio/ontology-go-sdk"
	"github.com/stretchr/testify/assert"
	"testing"
)

var testPassword = []byte("111111")

func TestOntologySdk_CreateWallet(t *testing.T) {
	testOntSdk := ontology_go_sdk.NewOntologySdk()
	wal, err := testOntSdk.CreateWallet("./wallet2.dat")
	assert.Nil(t, err)
	_,err = wal.NewDefaultSettingAccount(testPassword)
	assert.Nil(t, err)
	wal.Save()
}
