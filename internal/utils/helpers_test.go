package utils_test

import (
	"math"
	"testing"

	"github.com/wanaware/GCP-Sec/internal/utils"
)

func TestMean(t *testing.T) {
	tests := []struct {
		vals []float64
		want float64
	}{
		{[]float64{}, 0},
		{[]float64{5}, 5},
		{[]float64{1, 2, 3, 4, 5}, 3},
		{[]float64{10, 20}, 15},
	}
	for _, tc := range tests {
		got := utils.Mean(tc.vals)
		if got != tc.want {
			t.Errorf("Mean(%v) = %.2f, want %.2f", tc.vals, got, tc.want)
		}
	}
}

func TestMedian(t *testing.T) {
	tests := []struct {
		vals []float64
		want float64
	}{
		{[]float64{}, 0},
		{[]float64{5}, 5},
		{[]float64{1, 3, 2}, 2},           // odd count
		{[]float64{1, 2, 3, 4}, 2.5},      // even count
		{[]float64{10, 20, 30}, 20},
	}
	for _, tc := range tests {
		got := utils.Median(tc.vals)
		if got != tc.want {
			t.Errorf("Median(%v) = %.2f, want %.2f", tc.vals, got, tc.want)
		}
	}
}

func TestStdDev(t *testing.T) {
	// StdDev of constant values should be 0
	got := utils.StdDev([]float64{5, 5, 5, 5})
	if got != 0 {
		t.Errorf("StdDev of constant = %.4f, want 0", got)
	}

	// StdDev of {2, 4, 4, 4, 5, 5, 7, 9} = 2.0
	got = utils.StdDev([]float64{2, 4, 4, 4, 5, 5, 7, 9})
	if math.Abs(got-2.0) > 0.01 {
		t.Errorf("StdDev = %.4f, want ~2.0", got)
	}
}

func TestRound(t *testing.T) {
	tests := []struct {
		val    float64
		places int
		want   float64
	}{
		{3.14159, 2, 3.14},
		{3.145, 2, 3.15},
		{100.0, 0, 100},
	}
	for _, tc := range tests {
		got := utils.Round(tc.val, tc.places)
		if got != tc.want {
			t.Errorf("Round(%.5f, %d) = %.5f, want %.5f", tc.val, tc.places, got, tc.want)
		}
	}
}

func TestContainsAny(t *testing.T) {
	tests := []struct {
		s    string
		subs []string
		want bool
	}{
		{"FLOW_LOGS_DISABLED", []string{"FLOW_LOGS"}, true},
		{"FIREWALL_RULE", []string{"HTTP", "DATABASE"}, false},
		{"HTTP_LOAD_BALANCER", []string{"HTTP", "HTTPS"}, true},
		{"", []string{"TEST"}, false},
	}
	for _, tc := range tests {
		got := utils.ContainsAny(tc.s, tc.subs...)
		if got != tc.want {
			t.Errorf("ContainsAny(%q, %v) = %v, want %v", tc.s, tc.subs, got, tc.want)
		}
	}
}

func TestParseBool(t *testing.T) {
	trueVals := []string{"true", "True", "TRUE", "1", "yes", "YES", "y", "t"}
	falseVals := []string{"false", "False", "FALSE", "0", "no", "NO", "n", "f", "", "random"}

	for _, v := range trueVals {
		if !utils.ParseBool(v) {
			t.Errorf("ParseBool(%q) = false, want true", v)
		}
	}
	for _, v := range falseVals {
		if utils.ParseBool(v) {
			t.Errorf("ParseBool(%q) = true, want false", v)
		}
	}
}

func TestSafePercentage(t *testing.T) {
	tests := []struct {
		part, total int
		want        float64
	}{
		{0, 0, 0},
		{50, 100, 50},
		{1, 3, 33.333333333333336},
	}
	for _, tc := range tests {
		got := utils.SafePercentage(tc.part, tc.total)
		if math.Abs(got-tc.want) > 0.001 {
			t.Errorf("SafePercentage(%d, %d) = %.4f, want %.4f", tc.part, tc.total, got, tc.want)
		}
	}
}

func TestUniqueStrings(t *testing.T) {
	input := []string{"CIS", "PCI", "CIS", "HIPAA", "PCI"}
	got := utils.UniqueStrings(input)
	if len(got) != 3 {
		t.Errorf("UniqueStrings(%v) = %v, want 3 items", input, got)
	}
}

func TestTruncate(t *testing.T) {
	tests := []struct {
		s      string
		maxLen int
		want   string
	}{
		{"hello", 10, "hello"},
		{"hello world", 8, "hello..."},
		{"hi", 3, "hi"},
	}
	for _, tc := range tests {
		got := utils.Truncate(tc.s, tc.maxLen)
		if got != tc.want {
			t.Errorf("Truncate(%q, %d) = %q, want %q", tc.s, tc.maxLen, got, tc.want)
		}
	}
}
