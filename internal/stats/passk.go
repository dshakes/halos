package stats

import "fmt"

// PassAtK is the unbiased estimator of pass@k (Chen et al. 2021): the
// probability that at least one of k trials drawn without replacement from n
// trials with c passes succeeds, 1 - C(n-c,k)/C(n,k), computed as a product
// so it never overflows.
func PassAtK(n, c, k int) (float64, error) {
	if err := checkNCK(n, c, k); err != nil {
		return 0, err
	}
	if n-c < k {
		return 1, nil
	}
	p := 1.0
	for i := n - c + 1; i <= n; i++ {
		p *= 1 - float64(k)/float64(i)
	}
	return 1 - p, nil
}

// PassHatK is pass^k (tau-bench): the probability that all k trials drawn
// without replacement succeed, C(c,k)/C(n,k). It measures reliability, where
// pass@k measures capability.
func PassHatK(n, c, k int) (float64, error) {
	if err := checkNCK(n, c, k); err != nil {
		return 0, err
	}
	p := 1.0
	for i := 0; i < k; i++ {
		p *= float64(c-i) / float64(n-i)
	}
	return max(p, 0), nil
}

func checkNCK(n, c, k int) error {
	if n < 1 || c < 0 || c > n || k < 1 || k > n {
		return fmt.Errorf("stats: pass@k needs 1 <= k <= n and 0 <= c <= n (n=%d c=%d k=%d)", n, c, k)
	}
	return nil
}
