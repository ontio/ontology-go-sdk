package ontology_go_sdk

import (
	"fmt"
	"github.com/stretchr/testify/assert"
	"strings"
	"testing"
	"time"
)

func TestClaimRecord_SendCommit(t *testing.T) {
	sdk := NewOntologySdk()
	sdk.NewRpcClient().SetAddress("http://polaris1.ont.io:20336")
	gasPrice := uint64(500)

	claimStr := "eyJraWQiOiJkaWQ6b250OkFTejlOZENCVUdEclpZVGhuY2hGZkp0ZVFWcnUyUDNtcXEja2V5cy0xIiwidHlwIjoiSldULVgiLCJhbGciOiJPTlQtRVMyNTYifQ==.eyJjbG0tcmV2Ijp7Iklzc3VlciI6ImRpZDpvbnQ6QVN6OU5kQ0JVR0RyWllUaG5jaEZmSnRlUVZydTJQM21xcSIsIlN1YmplY3QiOiJkaWQ6b250OkFhcnJNQnkxaUdKU1o1VG1VUUNvak55VlZUdWdpUExQaWsifSwic3ViIjoiZGlkOm9udDpBYXJyTUJ5MWlHSlNaNVRtVVFDb2pOeVZWVHVnaVBMUGlrIiwidmVyIjoidjEuMCIsImNsbSI6eyIkcmVmIjoiJC5jbG0tcmV2In0sImlzcyI6ImRpZDpvbnQ6QVN6OU5kQ0JVR0RyWllUaG5jaEZmSnRlUVZydTJQM21xcSIsImV4cCI6MTU4NjQ5OTEwNCwiaWF0IjoxNTg2NDk4MTA1LCJAY29udGV4dCI6ImNsYWltOmNvbnRleHQiLCJqdGkiOiI1MzlhMzlmNWYyY2E1NzRlNTdkMjY2NzRiMDBhZTc5ZTBkODdiYjExMTNmODBlZWNmZDFkZDhjNThhOTNiM2NjIn0=.AZ1jo4XYus7+ovFK5FKr3l5GxJihfDUPlsiOhY4vyiRf283L8AYG7fIguE2HLUEDLIE7rGxc6jnU8/ts77MLo6U="
	strings.Split(claimStr, ".")
	claimId := "539a39f5f2ca574e57d26674b00ae79e0d87bb1113f80eecfd1dd8c58a93b3cb"
	wallet, _ := sdk.OpenWallet("./wallet.dat")
	pwd := []byte("111111")

	issuerOntid, _ := wallet.NewDefaultSettingIdentity(pwd)
	subjectOntid, _ := wallet.NewDefaultSettingIdentity(pwd)
	payer, err := wallet.GetAccountByAddress("ARqV7citgShDzBGiqVSNyXXM6jSCrAuwKG", pwd)
	assert.Nil(t, err)

	claimRecordContract := "5fc56b6c766b00527ac46c766b51527ac4616c766b00c306436f6d6d6974876c766b52527ac46c766b52c3647100616c766b51c3c0539c009c6c766b56527ac46c766b56c3640e00006c766b57527ac46232016c766b51c300c36c766b53527ac46c766b51c351c36c766b54527ac46c766b51c352c36c766b55527ac46c766b53c36c766b54c36c766b55c361527265fc006c766b57527ac462e9006c766b00c3065265766f6b65876c766b58527ac46c766b58c3645d00616c766b51c3c0529c009c6c766b5b527ac46c766b5bc3640e00006c766b57527ac462a8006c766b51c300c36c766b59527ac46c766b51c351c36c766b5a527ac46c766b59c36c766b5ac3617c6528026c766b57527ac46273006c766b00c309476574537461747573876c766b5c527ac46c766b5cc3644900616c766b51c3c0519c009c6c766b5e527ac46c766b5ec3640e00006c766b57527ac4622f006c766b51c300c36c766b5d527ac46c766b5dc361651b046c766b57527ac4620e00006c766b57527ac46203006c766b57c3616c756658c56b6c766b00527ac46c766b51527ac46c766b52527ac46161681953797374656d2e53746f726167652e476574436f6e746578746c766b00c3617c681253797374656d2e53746f726167652e4765746c766b53527ac46c766b53c300a06c766b56527ac46c766b56c364440061616c766b00c309206578697374656421617c084572726f724d736753c1681553797374656d2e52756e74696d652e4e6f7469667961006c766b57527ac462ee006154c56c766b54527ac46c766b54c36c766b00c3007cc46c766b54c351537cc46c766b54c36c766b51c3517cc46c766b54c36c766b52c3527cc46c766b54c361681853797374656d2e52756e74696d652e53657269616c697a656c766b55527ac461681953797374656d2e53746f726167652e476574436f6e746578746c766b00c36c766b55c3615272681253797374656d2e53746f726167652e50757461616c766b51c31320637265617465206e657720636c61696d3a206c766b00c3615272045075736854c1681553797374656d2e52756e74696d652e4e6f7469667961516c766b57527ac46203006c766b57c3616c756659c56b6c766b00527ac46c766b51527ac46161681953797374656d2e53746f726167652e476574436f6e746578746c766b00c3617c681253797374656d2e53746f726167652e4765746c766b52527ac46c766b52c3009c6c766b55527ac46c766b55c364480061616c766b00c30d206e6f74206578697374656421617c084572726f724d736753c1681553797374656d2e52756e74696d652e4e6f7469667961006c766b56527ac462a7016c766b52c361681a53797374656d2e52756e74696d652e446573657269616c697a656c766b53527ac46c766b53c353c3519c009c6c766b57527ac46c766b57c3644b0061616c766b00c31020696e76616c6964207374617475732e617c084572726f724d736753c1681553797374656d2e52756e74696d652e4e6f7469667961006c766b56527ac4621c016c766b53c351c36c766b51c3617c65ac01009c6c766b58527ac46c766b58c364440061616c766b51c30920696e76616c69642e617c084572726f724d736753c1681553797374656d2e52756e74696d652e4e6f7469667961006c766b56527ac462b9006c766b53c300537cc46c766b53c361681853797374656d2e52756e74696d652e53657269616c697a656c766b54527ac461681953797374656d2e53746f726167652e476574436f6e746578746c766b00c36c766b54c3615272681253797374656d2e53746f726167652e50757461616c766b51c30f207265766f6b6520636c61696d3a206c766b00c3615272045075736854c1681553797374656d2e52756e74696d652e4e6f7469667961516c766b56527ac46203006c766b56c3616c756653c56b6c766b00527ac46161681953797374656d2e53746f726167652e476574436f6e746578746c766b00c3617c681253797374656d2e53746f726167652e4765746c766b51527ac4616c766b00c309207374617475733a206c766b51c3615272045075736854c1681553797374656d2e52756e74696d652e4e6f74696679616c766b51c36c766b52527ac46203006c766b52c3616c756657c56b6c766b00527ac46c766b51527ac4616c766b00c3c06c766b51c3c09c009c6c766b52527ac46c766b52c3640f0061006c766b53527ac4627900006c766b54527ac4624800616c766b00c36c766b54c3517f6c766b51c36c766b54c3517f9c009c6c766b55527ac46c766b55c3640e00006c766b53527ac4623800616c766b54c351936c766b54527ac46c766b54c36c766b00c3c09f6c766b56527ac46c766b56c363a3ff516c766b53527ac46203006c766b53c3616c7566"
	sdk.NeoVM.DeployNeoVMSmartContract(gasPrice, 200000000, payer, true, claimRecordContract, "", "", "", "", "")
	time.Sleep(6 * time.Second)

	con, _ := issuerOntid.GetControllerByIndex(1, pwd)
	txHash, err := sdk.Native.OntId.RegIDWithPublicKey(gasPrice, 20000, payer, payer, issuerOntid.ID, con)
	assert.Nil(t, err)
	time.Sleep(6 * time.Second)
	event, err := sdk.GetSmartContractEvent(txHash.ToHexString())
	assert.Nil(t, err)
	assert.Equal(t, event.State, byte(1))

	txHash, err = sdk.NeoVM.ClaimRecord.SendCommit(issuerOntid, pwd, subjectOntid.ID, claimId, payer, gasPrice, 20000)
	assert.Nil(t, err)
	time.Sleep(6 * time.Second)
	event, err = sdk.GetSmartContractEvent(txHash.ToHexString())
	assert.Nil(t, err)
	assert.Equal(t, event.State, byte(1))
	fmt.Println("SendCommit event:", event.Notify)

	status, err := sdk.NeoVM.ClaimRecord.GetStatus(claimId)
	assert.Nil(t, err)
	fmt.Println("befor revoke status:", status)

	txHash, err = sdk.NeoVM.ClaimRecord.SendRevoke(issuerOntid, pwd, claimId, payer, 200000, gasPrice)
	time.Sleep(6 * time.Second)
	event, err = sdk.GetSmartContractEvent(txHash.ToHexString())
	assert.Nil(t, err)
	assert.Equal(t, event.State, byte(1))
	fmt.Println("SendRevoke event:", event.Notify)

	status, err = sdk.NeoVM.ClaimRecord.GetStatus(claimId)
	assert.Nil(t, err)
	fmt.Println("after revoke status:", status)
}
