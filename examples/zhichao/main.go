package main

import (
	"fmt"
	ontology_go_sdk "github.com/ontio/ontology-go-sdk"
	"github.com/ontio/ontology/common/password"
	"github.com/ontio/ontology/smartcontract/service/native/global_params"
	"os"
	"strconv"
	"strings"
	"time"
)

func main() {
	gasPrice := uint64(2500)
	defGasLimit := uint64(20000000)
	args := os.Args
	if len(args) <= 2 {
		fmt.Println("please input: ", "walletFile address [gaslimit]")
		return
	}
	walletFileStr := os.Args[1]
	addressStr := os.Args[2]
	gasLimit := defGasLimit
	if len(os.Args) > 3 {
		gasLimitStr := os.Args[3]
		temp, err := strconv.ParseUint(gasLimitStr, 10, 64)
		if err != nil {
			fmt.Println("gasLimit error:", err)
			return
		}
		gasLimit = temp
	}
	destroyedContract := getDestroyedContract()

	sdk := ontology_go_sdk.NewOntologySdk()
	sdk.NewRpcClient().SetAddress("http://dappnode2.ont.io:20336")
	//sdk.NewRpcClient().SetAddress("http://polaris2.ont.io:20336")

	walletFileArr := strings.Split(walletFileStr, ",")
	addressArr := strings.Split(addressStr, ",")
	if len(walletFileArr) != len(addressArr) {
		fmt.Println("wallet file number must be equal address")
		return
	}
	var accArr []*ontology_go_sdk.Account
	for i, f := range walletFileArr {
		wa, err := sdk.OpenWallet(f)
		if err != nil {
			fmt.Println(err)
			return
		}
		passwd, err := password.GetAccountPassword()
		if err != nil {
			fmt.Printf("input password error: %s\n", err)
			return
		}
		acc, err := wa.GetAccountByAddress(addressArr[i], passwd)
		if err != nil {
			fmt.Println(err)
			return
		}
		accArr = append(accArr, acc)
	}

	fmt.Println("start check contract address, it needs a few minutes")
	//检查地址
	checkContractAddr(destroyedContract, sdk)
	fmt.Println("check contract address success")

	tx, err := sdk.Native.GlobalParams.NewAddDestroyedContractTransaction(gasPrice, gasLimit, global_params.ADD_DESTROYED_CONTRACT, destroyedContract)
	if err != nil {
		fmt.Println("NewAddDestroyedContractTransaction failed:", err)
		return
	}
	for _, acc := range accArr {
		err = sdk.SignToTransaction(tx, acc)
		if err != nil {
			fmt.Println("sign tx failed:", err)
			return
		}
	}
	if true {
		return
	}

	txhash, err := sdk.SendTransaction(tx)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("AddDestroyedContract,txHash:", txhash.ToHexString())
	sdk.WaitForGenerateBlock(40*time.Second, 1)
	evt, err := sdk.GetSmartContractEvent(txhash.ToHexString())
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("AddDestroyedContract, evt:", evt)
}

func checkContractAddr(conAddr []string, sdk *ontology_go_sdk.OntologySdk) {
	special := "80fcdb0099ace9a2df6ab010a52edb0a07687559,d034792f80deeacd983dc257d29784ea71a1d5ec,6b9271d8d853ae7a50a03c33a21ef2ce6761a3d8"
	finish := 0
	for _, addr := range conAddr {
		_, err := sdk.GetSmartContract(addr)
		finish++
		if finish%20 == 0 {
			fmt.Println("has checked contract number:", finish)
		}
		if err != nil && strings.Contains(err.Error(), "UNKNOWN CONTRACT") {
			continue
		}
		if strings.Contains(special, addr) {
			continue
		} else {
			panic("unexpected contract address:" + addr)
		}
	}
}

func getDestroyedContract() []string {
	return []string{
		"c316858346ac133a6f3d0149ca7257a2a4e16783",
		"4cfbe5d9e6b6d2e58f63b2883b26b540e0119c71",
		"4e4a9b860fb7ffba41f91ea112712191bd7eca53",
		"95adaa30262e21cefe07bb99624d6249ce0b170d",
		"eab757b91e95cc6bcb5776215e21141fa05c5e04",
		"3cb96185093518e7f71bff1b26ca5dadc0a5522b",
		"60934a39e630c3c26247e327e15b78417fc3c8c1",
		"662b97beafc697177a85e7fadb55e7bdfc9f5b15",
		"93a67db2e2c28e70d49c3abd5d4cfba93828bcf8",
		"25e6031fc4545ca436f9219d35044560caedc2b0",
		"1924589e8a009d4d541ef138513df35824fcf142",
		"d3b733f12df9a6efb13ca547be5ee4e4dbe6d41e",
		"c316858346ac133a6f3d0149ca7257a2a4e16783",
		"4cfbe5d9e6b6d2e58f63b2883b26b540e0119c71",
		"4e4a9b860fb7ffba41f91ea112712191bd7eca53",
		"95adaa30262e21cefe07bb99624d6249ce0b170d",
		"eab757b91e95cc6bcb5776215e21141fa05c5e04",
		"3cb96185093518e7f71bff1b26ca5dadc0a5522b",
		"60934a39e630c3c26247e327e15b78417fc3c8c1",
		"662b97beafc697177a85e7fadb55e7bdfc9f5b15",
		"93a67db2e2c28e70d49c3abd5d4cfba93828bcf8",
		"25e6031fc4545ca436f9219d35044560caedc2b0",
		"1924589e8a009d4d541ef138513df35824fcf142",
		"d3b733f12df9a6efb13ca547be5ee4e4dbe6d41e",
		"afe613d7f7eab00d90db857b782586d6b21fa037",
		"e8000e6f23ef1a47be59a68d4707a3770d1ad453",
		"96a0e1ded874c0ae748c0210b9b76d2364b29aac",
		"15dc8b969d3ca0462fb3a0ee10a7e510c8ba6f63",
		"1af954143aa80b9b0847b1ada67dbb50ed9d58dc",
		"ee1cd92bc5477ffad59a04d0a75a365c714429e0",
		"5ebe9973d52a97535f5854501fc3cd11b2119ee5",
		"41ad2ef4767a835b88b22d2120d0ba7f0b596322",
		"991bab8e7b208824c8cf3dfe23f7cefbc5870f0b",
		"3081fb6a2b72d5b1a78111886b37bee48b7f5965",
		"20e2322eb48f0aeda8f9208280aaa6d15c46d769",
		"b9f64ec9db8a3692f830b42fa34cfebf789accd4",
		"ad92b0b1eb1fc3c27514c878c9f1e35d6a76fc81",
		"ee79ceec7fbc85cc8992cfdfcda5502c29d0ced8",
		"fa3211fa554f69a28d07aafed368d7d6570d3ff7",
		"894ad88705d1510f21c35f7b7b21674a192f1d57",
		"1e6a50be71cb6f683955b57c11bfbd48a73dd598",
		"e93a6e774bdfab36ee1252d693a0b054eccdbdc3",
		"1df56f20ee743e34f88c452e187a49ba3968bfe6",
		"aa1d67409d00bf1dae16a321454b91022e5318ec",
		"352ba362f846411bd93e1166d24fed544edd9c9c",
		"5018fbd6733cbbc3125f9f8afd967329bcf2d912",
		"383ea6f4102c44aa0a53429a30088463282a30ef",
		"0567fd3619bb0a3d35f13ca9bf25dedc70dabc0a",
		"f6a77f50393380bde5476cc4338ab2ae1ea37ac3",
		"8ae74af15b0c168c736f9955816232e2cfdcad1d",
		"1a8d1cba52758e2cec2bf9fe79289435db7fe29d",
		"00d98332521788a152131010a50765dc1c78b2a6",
		"c677d549d7555de4c4829f09ede69f7bdcba74be",
		"9800ab054db022fd1557d5bb7b3230127bb4c0e8",
		"b387e2c32055cce440628a2d35d32fb1b24f3424",
		"d7a41d8f2ae1d751cb923288aafd010983271c24",
		"c3fdaf1ba69f78dde634f500d69e88b4fe9b5503",
		"426106a4243c1dc17ce497b84c840765157b2e38",
		"bd2f16e337572948e9e9dd647961d1cf0db5c3af",
		"6043e531c3016400b87e8dd4ca8f07f1a8bbb58a",
		"f9514d3ad49a10c93ee0a9715579291b40af6819",
		"15e84e180a6f6c2de306e6b3f2ed1c681a78dbe4",
		"974de39582aa2aa060ba7dfb40535685a20f091b",
		"a9627f953c1765baa61673bf22e3038b62ed66b0",
		"adb794169063827a4edb33dd7435b0183f28f6a1",
		"a93a4379a47e7ebd98793a3afffb31d8855a3dc1",
		"f1839f2d0c4ca3553f6523afd26906e0f17c64be",
		"aba1e3f68fe45260a98bb707144d391a1f81d323",
		"bc810769ea51a188f3b722611ca7bc38dc711646",
		"803a0fed1fe42befc30f3ffca46923fafd276f0d",
		"932dde12bedf784332ac000f57590c108a2cc41d",
		"bc95aaf838cf5f6c18a4781a8bd895a422c7de9c",
		"1f00d76afcb3ca5734d834703fedd1cabf8ec8d7",
		"f2a0a4ea9a6c6ba6e23be0f58c75a5e984f9a712",
		"cc8ca2a1e10ff02feb6313b3fa347d08a5981b22",
		"1db77d641787a84d1032dc1c4eae8e4cb8f934a2",
		"45f93dada46c736d2c8702407e57e23ce51878d2",
		"c2edda6cde43dd4e00d3e5053306f8fb4ee52ce3",
		"2a8f0267c38eecffd1c0823fae777e0237265ee9",
		"803a0fed1fe42befc30f3ffca46923fafd276f0d",
		"771e4d3a9ca2d1135a88ee3f37fe65e602e72f45",
		"b2578ee6370f932dbc3e9ab67779c9a001a1add7",
		"093c94d817ef0e1b5e37898f2d43fd63767d2fa6",
		"4fce156bbcc206eeede236fa13bdb721aaa9b70e",
		"0944abd87b6907efd05a7a724e65010b9a5787bc",
		"dcba8e32ab89a0e27d4350118bfd482f531c02cb",
		"7c369922222dfc4cd7ff9939d6d36868cb33d138",
		"3ffe568f63f6e8ebaf61e24d291fbd9acd7201dc",
		"1d885fdb17188d3f5cdb25e322623deb690c05b4",
		"9dd2ca7e20cbf2715d56da1f8e3e19cea9f04d5b",
		"932dde12bedf784332ac000f57590c108a2cc41d",
		"ad944c6ddd5752866d81a7743c7df3b390f6fe55",
		"b1629d1e11b338aa11c18920b86d9895fb1f060c",
		"c76f675caa6908eaf746ce338abde89f6037dcf5",
		"dcada0d02ec57ad172ab9f536dbf7f3aeed312ae",
		"07af3fec7874def611f0f435df6bc65344315029",
		"14ff98e5362296cb02cbfc72a92dd1cee72ecc11",
		"f4cfb146e679651261b4e01dab19c4b138b90186",
		"3b07546444c09ed3475086a1381102635cdeb007",
		"35ea02c6c3e0144f75fd1c62d4693bd6af37ce91",
		"d49bef9c7686fd672e5efde40899325d9f61c56e",
		"5ee23ca793e2069fe3b8f231583508a0fe0449ad",
		"59f9fb269391ea0242a7632201b0a154e6d09b2c",
		"7bd02e7c26cd9f6d40fe9628e068d5c2597e60e3",
		"81f6ac5e46e8471f078cfe16d47b0d1a81f549c9",
		"d5bfee3988bbdd4161c65cbe0cc7326c56ad6aa8",
		"a7eb4786fe9d1b6d534dac165f68b5f2568bb01d",
		"0b4cd2c85892f7a759e5f21aa33a876aa090855a",
		"ef924d1ff563381364c56d84256e88711697234c",
		"b9a9ea7695cf92a610e519c8d00fd3aade515ba0",
		"6cc0b7f9f53b38d9d8c7d42a930a830ce54d397b",
		"6cc07af5dd69c878c02c752209899b4c1e74e9c0",
		"067bf820e8f5eba7e96e13ef97163ce921b7d570",
		"f2ad5f6d82cfdd82f1c9cda3a0f08cad8ab82144",
		"b2fc52315b9b1f1dca93720109aa7270511ced7c",
		"b03b5a4f4ea36d6a8ab25a01a41874b6261ca5d6",
		"000aab331972d2d70d54bec6642474306a40ebcd",
		"bd0fd6617449e3507d8c3f4de31a728ea737515b",
		"4ba9d00395066f0ea724da76b14e1c5a11ac7701",
		"8bdda24ddced35e9e765f5707cb5abc9c6d05c2f",
		"9660a497399d2482bcbd1c43676cf29f1bd55cdf",
		"4206c4c5e02f8a376573a6e75691f021572ae2f7",
		"a28a058e7de5ad951278e5dd80cdd8b4c91fe280",
		"84337b6e51d17033853c312f3490c2a47a8da261",
		"1ccac4518c54ca5fa1e4d0823858c9ff1d86f672",
		"2293650283f0ccee042e25b493905d1495aad699",
		"49c345325975ebe44316d29d15ad467225edb8fa",
		"e63bab465f404e83da9996deba3ca3638b471c9d",
		"e0e7e2fb5bb57513037f60cd85a82c307ad6a55f",
		"60a066ad7efbf1d15e7bf2c018ad46c821b84702",
		"913b56856eb50e1829a035c07fd3dd566793c6cd",
		"88c1758e83bb8d452a28e06e1f893ad822f07378",
		"cc308a4eb2a87dcd0a8a4255b22d26958205f91b",
		"e93d70d02f2605da93cdfb7c8d42837d21d6053f",
		"dab8b901516e0265ba68c0422fee65b3589ba739",
		"22f31250516874d6c559c55aeae682017d6a414d",
		"b10a7e45aefdb7eda128833653886475f0ba27af",
		"838d6cdf2d97ec65bbcdb4886a7f054744b0fece",
		"6b7dca09545a99a6aacdb175cc1cb9dea009c220",
		"15456a89aa9372a9d7a69f7be399609899e55822",
		"5296dce40a9d58ca203b13a456b281e136ec7c73",
		"d6614f3adae9f5adfe11a7e7abf31fe43689cb09",
		"9a1258d6999fa86e35573af6c0c554d2c7c937b9",
		"17a9057a8648e43fb6073c60e40973dc1b888180",
		"29f28cd004aa0c3acf96faffe9ab298ff2fecd53",
		"1b3bd398bbe91619a9bde19d910a26035f869e3d",
		"2327be612cf6126bc54f5e8d77dcf2faf1883e6e",
		"adb0d4d28e6374fdda22238356cba34341f6a239",
		"ff9bc226c37bebeaccf203443fb97fc32e2d0822",
		"d00452534aa7a2f2a9c6afbf562c4048626eb918",
		"8417f13b1f2c3e38f6418d32dfa14ad8d9e9aa88",
		"249ca3d97864cc2f8e2db89545f18c169cc80dee",
		"a3758613dfd5601065124146185005ad4f40570c",
		"152e66e28fc002687a75e419834dff3ca082f732",
		"908c88f18ac19d539794978fda4930c55f0859ac",
		"4685c3cf4f0123aa7181bf0fc054470ecb2979e0",
		"f3cb2f642de8333ce105ad449666b06c855025fe",
		"d9ff5151b48a09418e8c1af72d899ec058824774",
		"61b741dd752fa504fe11388fa5cfd3cc9ee6cd53",
		"fed9f8da3658d6844ffe186d4793e8a9a717d508",
		"6fce2bc7505521e25dbd56a501ce772fa31fa36d",
		"47475f1d312a5e041752d209a92325d9eec0e176",
		"b962d4bf85abb19aa315f8ff097a42f7d722887b",
		"244cd88e20050c7af25881706d3dfbd470e8eb58",
		"10290e0c68b4c960806924c186c92c04fddb98ea",
		"0e0543c8af5c597e3e7a45f582a9d0044740d502",
		"2be88c8032966101c73bcda96d9b7e817e2edca4",
		"9dbbc2d836e22a4bed814ed6843d595f2a7180ff",
		"83b4db3d6023651d6a4157e3cd2fc486ef3b69d0",
		"ed4ae41c502aa9315684783f5a8c6ffadaaa1f8a",
		"80fcdb0099ace9a2df6ab010a52edb0a07687559",
		"d034792f80deeacd983dc257d29784ea71a1d5ec",
		"6b9271d8d853ae7a50a03c33a21ef2ce6761a3d8",
	}
}
