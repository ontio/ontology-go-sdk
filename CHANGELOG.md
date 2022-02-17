# ChangeLog

## 1、Add ONT interface

### 1、Get balance V2

```
ontSdk.Native.Ont.BalanceOfV2(address common.Address) (*big.Int, error)
```

### 2、 Transfer V2

```
ontSdk.Native.Ont.TransferV2(gasPrice, gasLimit uint64, from *Account, to common.Address, amount *big.Int) (common.Uint256, error)
```

### 3、 Multiple Transfer V2

```
ontSdk.Native.Ont.MultiTransferV2(gasPrice, gasLimit uint64, states []*ont.State, signer *Account) (common.Uint256, error)
```

A multi transfer does more than one transfer of ONT in one transaction.

### 4、Approve V2

```
ontSdk.Native.Ont.ApproveV2(gasPrice, gasLimit uint64, from *Account, to common.Address, amount *big.Int) (common.Uint256, error)
```

### 5、 Allowance V2

```
ontSdk.Native.Ont.AllowanceV2(from, to common.Address) (*big.Int, error)
```

### 6、 Transfer From V2

```
ontSdk.Native.Ont.TransferFromV2(gasPrice, gasLimit uint64, sender *Account, from, to common.Address, amount *big.Int) (common.Uint256, error)
```

## 2、Add ONG interface

### 1、 Get balance V2

```
ontSdk.Native.Ong.BalanceOfV2(address common.Address) (*big.Int, error)
```

### 2、 Transfer V2

```
ontSdk.Native.Ong.TransferV2(gasPrice, gasLimit uint64, from *Account, to common.Address, amount *big.Int) (common.Uint256, error)
```

### 3、 Multiple Transfer V2

```
ontSdk.Native.Ong.MultiTransferV2(gasPrice, gasLimit uint64, states []*ont.State, signer *Account) (common.Uint256, error)
```

A multi transfer does more than one transfer of ONG in one transaction.

### 4、 Approve V2

```
ontSdk.Native.Ong.ApproveV2(gasPrice, gasLimit uint64, from *Account, to common.Address, amount *big.Int) (common.Uint256, error)
```

### 5、 Approve Balance V2

```
ontSdk.Native.Ong.AllowanceV2(from, to common.Address) (*big.Int, error)
```

### 6、 TransferFrom V2

```
ontSdk.Native.Ong.TransferFrom(gasPrice, gasLimit uint64, sender *Account, from, to common.Address, amount *big.Int) (common.Uint256, error)
```

### 7、 Withdraw ONG V2

```
ontSdk.Native.Ong.WithdrawONG(gasPrice, gasLimit uint64, address *Account, amount *big.Int) (common.Uint256, error)
```

### 8、 Get unbound ONG V2

```
ontSdk.Native.Ong.UnboundONGV2(address common.Address) (*big.Int, error)
```

3、Modify TransferOng Event Parse
```
type TransferEventV2 struct {
	FuncName string
	From     string
	To       string
	Amount   *big.Int
}

ParseNativeTransferEventV2(event *sdkcom.NotifyEventInfo) (*TransferEventV2, error) 
```