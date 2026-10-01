package rename

// OrderTotal is the amount charged for an order with 10% tax.
func OrderTotal(prices []int) int { return calc(prices, 10) }
