package rename

func calc(prices []int, taxPct int) int {
	sum := 0
	for _, p := range prices {
		sum += p
	}
	return sum + sum*taxPct/100
}
