package cryptoutil

import (
	"crypto/ecdh"
	"fmt"
	"math/big"
	"sync"
)

var primes sync.Map

// RFC 2409 groups 1/2 and RFC 3526 MODP groups. Larger RFC 3526 primes
// are generated from their defining formula, using integer fixed-point pi.
func NewGroup(id uint16) (DHGroup, error) {
	switch id {
	case 19:
		return NewECDH(ecdh.P256(), true), nil
	case 20:
		return NewECDH(ecdh.P384(), true), nil
	case 21:
		return NewECDH(ecdh.P521(), true), nil
	case 31:
		return NewECDH(ecdh.X25519(), false), nil
	}
	bits, constant := 0, int64(0)
	switch id {
	case 1:
		bits = 768
		constant = 149686
	case 2:
		bits = 1024
		constant = 129093
	case 5:
		bits = 1536
		constant = 741804
	case 14:
		bits = 2048
		constant = 124476
	case 15:
		bits = 3072
		constant = 1690314
	case 16:
		bits = 4096
		constant = 240904
	case 17:
		bits = 6144
		constant = 929484
	case 18:
		bits = 8192
		constant = 4743158
	default:
		return nil, fmt.Errorf("unsupported DH group %d", id)
	}
	cached, ok := primes.Load(id)
	var p *big.Int
	if ok {
		p = cached.(*big.Int)
	} else {
		// Extra guard bits bound accumulated integer rounding far below one unit
		// at the formula's floor; the resulting values are the published RFC primes.
		precision := bits + 128
		scale := new(big.Int).Lsh(big.NewInt(1), uint(precision))
		atan := func(divisor int64) *big.Int {
			power := new(big.Int).Quo(new(big.Int).Set(scale), big.NewInt(divisor))
			out := new(big.Int)
			square := big.NewInt(divisor * divisor)
			for n := int64(0); power.Sign() != 0; n++ {
				term := new(big.Int).Quo(power, big.NewInt(2*n+1))
				if n%2 == 0 {
					out.Add(out, term)
				} else {
					out.Sub(out, term)
				}
				power.Quo(power, square)
			}
			return out
		}
		pi := new(big.Int).Sub(new(big.Int).Mul(big.NewInt(16), atan(5)), new(big.Int).Mul(big.NewInt(4), atan(239)))
		pi.Rsh(pi, uint(precision-(bits-130)))
		pi.Add(pi, big.NewInt(constant))
		pi.Lsh(pi, 64)
		p = new(big.Int).Lsh(big.NewInt(1), uint(bits))
		p.Sub(p, new(big.Int).Lsh(big.NewInt(1), uint(bits-64)))
		p.Sub(p, big.NewInt(1))
		p.Add(p, pi)
		primes.Store(id, p)
	}
	return &modpGroup{prime: p, g: big.NewInt(2), size: bits / 8}, nil
}
