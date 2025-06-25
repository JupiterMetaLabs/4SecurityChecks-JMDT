package PKSignatureCheck

import (
    "errors"
    "math/big"

    "github.com/ethereum/go-ethereum/core/types"
    "github.com/ethereum/go-ethereum/crypto"
    "github.com/jupitermetalabs/jmdt4checks/Config"
    "github.com/jupitermetalabs/jmdt4checks/Config/helper"
)

// PKSignatureCheck recomputes the signing hash (legacy, EIP-2930 or EIP-1559),
// recovers the public key via secp256k1, and verifies it matches txn.From.
func PKSignatureCheck(txn *Config.Transaction) (bool, error) {
    if txn == nil {
        return false, errors.New("transaction is nil")
    }
    if txn.V == nil || txn.R == nil || txn.S == nil {
        return false, errors.New("signature values missing")
    }
    if txn.From == nil {
        return false, errors.New("sender address missing")
    }

    // Decide tx type: EIP-1559 only if both fields are non-nil AND non-zero
    isDynamic := txn.MaxFeePerGas != nil &&
                 txn.MaxPriorityFeePerGas != nil &&
                 (txn.MaxFeePerGas.Sign() > 0 || txn.MaxPriorityFeePerGas.Sign() > 0)

    // 1) Reconstruct the unsigned go-ethereum Transaction
    var ethTx *types.Transaction
    switch {
    case isDynamic:
        inner := &types.DynamicFeeTx{
            ChainID:    txn.ChainID,
            Nonce:      txn.Nonce,
            To:         txn.To,
            Value:      txn.Value,
            GasTipCap:  txn.MaxPriorityFeePerGas,
            GasFeeCap:  txn.MaxFeePerGas,
            Gas:        txn.GasLimit,
            Data:       txn.Data,
            AccessList: helper.ConvertAccessList(txn.AccessList),
        }
        ethTx = types.NewTx(inner)

    case len(txn.AccessList) > 0:
        inner := &types.AccessListTx{
            ChainID:    txn.ChainID,
            Nonce:      txn.Nonce,
            To:         txn.To,
            Value:      txn.Value,
            GasPrice:   txn.GasPrice,
            Gas:        txn.GasLimit,
            Data:       txn.Data,
            AccessList: helper.ConvertAccessList(txn.AccessList),
        }
        ethTx = types.NewTx(inner)

    default:
        inner := &types.LegacyTx{
            Nonce:    txn.Nonce,
            To:       txn.To,
            Value:    txn.Value,
            GasPrice: txn.GasPrice,
            Gas:      txn.GasLimit,
            Data:     txn.Data,
        }
        ethTx = types.NewTx(inner)
    }

    // 2) Compute the signing hash (EIP-155/London)
    signer := types.NewLondonSigner(txn.ChainID)
    hash := signer.Hash(ethTx).Bytes()

    // 3) Pack R, S, V into the 65-byte [R||S||recoveryID] signature
    sig, err := packSignature(txn.R, txn.S, txn.V, txn.ChainID, isDynamic)
    if err != nil {
        return false, err
    }

    // 4) Recover the public key
    pubKey, err := crypto.SigToPub(hash, sig)
    if err != nil {
        return false, err
    }

    // 5) Derive the address and compare
    recoveredAddr := crypto.PubkeyToAddress(*pubKey)
    if recoveredAddr != *txn.From {
        return false, nil
    }
    return true, nil
}

// packSignature builds the 65-byte [R||S||recoveryID] blob.
// Handles both legacy V=27/28, EIP-155 V = 35+2*chainID+recID, and EIP-1559 V = 0/1.
func packSignature(r, s, v, chainID *big.Int, isEIP1559 bool) ([]byte, error) {
    rBytes, sBytes := r.Bytes(), s.Bytes()
    var recID byte
    vUint := v.Uint64()

    if isEIP1559 {
        // EIP-1559: V is already the recovery ID (0 or 1)
        if vUint > 1 {
            return nil, errors.New("invalid V for EIP-1559: must be 0 or 1")
        }
        recID = byte(vUint)
    } else {
        // Legacy or EIP-2930 transactions
        switch {
        case vUint == 27 || vUint == 28:
            // Pre-EIP-155
            recID = byte(vUint - 27)
        default:
            // EIP-155: v = recID + 35 + 2*chainID
            twoChain := new(big.Int).Mul(big.NewInt(2), chainID)
            base := new(big.Int).Add(big.NewInt(35), twoChain)
            rid := new(big.Int).Sub(v, base)
            if rid.Sign() < 0 || rid.BitLen() > 1 {
                return nil, errors.New("invalid V for EIP-155")
            }
            recID = byte(rid.Uint64())
        }
    }

    sig := make([]byte, 65)
    copy(sig[32-len(rBytes):32], rBytes)
    copy(sig[64-len(sBytes):64], sBytes)
    sig[64] = recID
    return sig, nil
}