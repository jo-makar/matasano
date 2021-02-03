package bigint

import (
    "math/big"
)

func Zero() *big.Int {
    return big.NewInt(0)
}

func Add(a, b *big.Int) *big.Int {
    return Zero().Add(a, b)
}

func Mul(a, b *big.Int) *big.Int {
    return Zero().Mul(a, b)
}

func Mod(a, b *big.Int) *big.Int {
    return Zero().Mod(a, b)
}

func Pow(a, b *big.Int) *big.Int {
    return Zero().Exp(a, b, nil)
}
