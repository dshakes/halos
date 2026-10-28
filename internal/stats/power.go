package stats

import (
	"errors"
	"fmt"
	"math"
)

// NormalQuantile is the standard normal inverse CDF at p in (0,1).
func NormalQuantile(p float64) float64 { return math.Sqrt2 * math.Erfinv(2*p-1) }

func checkPower(sd, alpha, power float64) error {
	switch {
	case !(sd > 0) || math.IsInf(sd, 0):
		return fmt.Errorf("stats: sd must be > 0, got %v", sd)
	case !(alpha > 0 && alpha < 1):
		return fmt.Errorf("stats: alpha must be in (0,1), got %v", alpha)
	case !(power > 0 && power < 1):
		return fmt.Errorf("stats: power must be in (0,1), got %v", power)
	}
	return nil
}

// SampleSize is the per-arm sample size of a two-sided two-sample z-test
// that detects an absolute difference mde between arm means, with per-unit
// standard deviation sd, at level alpha and the given power:
// n = 2 (z(1-alpha/2) + z(power))^2 sd^2 / mde^2, rounded up.
func SampleSize(sd, mde, alpha, power float64) (int, error) {
	if err := checkPower(sd, alpha, power); err != nil {
		return 0, err
	}
	if !(mde > 0) || math.IsInf(mde, 0) {
		return 0, fmt.Errorf("stats: mde must be > 0, got %v", mde)
	}
	z := NormalQuantile(1-alpha/2) + NormalQuantile(power)
	n := math.Ceil(2 * z * z * sd * sd / (mde * mde))
	if n > math.MaxInt32 {
		return 0, errors.New("stats: sample size overflows; the mde is too small for this sd")
	}
	return int(n), nil
}

// MDE is the smallest absolute difference SampleSize's test detects with n
// units per arm (its inverse).
func MDE(n int, sd, alpha, power float64) (float64, error) {
	if err := checkPower(sd, alpha, power); err != nil {
		return 0, err
	}
	if n < 2 {
		return 0, fmt.Errorf("stats: n must be >= 2, got %d", n)
	}
	z := NormalQuantile(1-alpha/2) + NormalQuantile(power)
	return z * sd * math.Sqrt(2/float64(n)), nil
}
