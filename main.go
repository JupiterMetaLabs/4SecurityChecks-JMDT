package main

import (
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/jupitermetalabs/jmdt4checks/Config"
	sigcheck "github.com/jupitermetalabs/jmdt4checks/Operations/PKSignatureCheck"
)

type impl struct {
	NewTransaction func(from *common.Address,chainID *big.Int,nonce uint64,to *common.Address,value *big.Int,data []byte,gasLimit uint64,gasPrice *big.Int,maxPriorityFeePerGas *big.Int,maxFeePerGas *big.Int,accessList Config.AccessList,v, r, s *big.Int) *Config.Transaction
	PKSignatureChecker func(txn *Config.Transaction) (bool, error)
}

func NewTransaction(
    from *common.Address, chainID *big.Int,
    nonce uint64, to *common.Address,
    value *big.Int, data []byte,
    gasLimit uint64, gasPrice *big.Int,
    maxPriorityFeePerGas *big.Int, maxFeePerGas *big.Int,
    accessList Config.AccessList, v, r, s *big.Int ) *Config.Transaction {

    return &Config.Transaction{
        From:                from,
        ChainID:             chainID,
        Nonce:               nonce,
        To:                  to,
        Value:               value,
        Data:                data,
        GasLimit:            gasLimit,
        GasPrice:            gasPrice,
        MaxPriorityFeePerGas: maxPriorityFeePerGas,
        MaxFeePerGas:         maxFeePerGas,
        AccessList:          accessList,
        V:                   v,
        R:                   r,
        S:                   s,
    }

}

func PKSignatureChecker(txn *Config.Transaction) (bool, error) {
	return sigcheck.PKSignatureCheck(txn)
}
