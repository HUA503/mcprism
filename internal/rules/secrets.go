package rules

import (
	"math"
	"regexp"
)

// knownTokenPatterns 是可直接判定类型的凭据格式。命中即按真实凭据处理，
// 与环境变量的名字无关。
var knownTokenPatterns = []struct {
	kind string
	re   *regexp.Regexp
}{
	{"AWS access key", regexp.MustCompile(`\b(?:AKIA|ASIA)[0-9A-Z]{16}\b`)},
	{"Google API key", regexp.MustCompile(`\bAIza[0-9A-Za-z_-]{35}\b`)},
	{"GitHub personal access token", regexp.MustCompile(`\bghp_[A-Za-z0-9]{36}\b`)},
	{"GitHub fine-grained token", regexp.MustCompile(`\bgithub_pat_[A-Za-z0-9_]{82}\b`)},
	{"GitHub OAuth token", regexp.MustCompile(`\bgho_[A-Za-z0-9]{36}\b`)},
	{"Slack token", regexp.MustCompile(`\bxox[baprs]-[A-Za-z0-9-]{10,72}\b`)},
	{"Stripe live secret key", regexp.MustCompile(`\bsk_live_[0-9a-zA-Z]{24}\b`)},
	{"GitLab personal access token", regexp.MustCompile(`\bglpat-[A-Za-z0-9_-]{20}\b`)},
	{"OpenAI-style API key", regexp.MustCompile(`\bsk-[A-Za-z0-9_-]{20,}\b`)},
	{"npm access token", regexp.MustCompile(`\bnpm_[A-Za-z0-9]{36}\b`)},
	{"JWT", regexp.MustCompile(`\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b`)},
}

func detectKnownToken(v string) (string, bool) {
	for _, p := range knownTokenPatterns {
		if p.re.MatchString(v) {
			return p.kind, true
		}
	}
	return "", false
}

// shannonEntropy 返回字符串的香农熵（bits/字符）。随机生成的凭据通常
// 明显高于自然语言或十六进制摘要。
func shannonEntropy(s string) float64 {
	runes := []rune(s)
	n := float64(len(runes))
	if n == 0 {
		return 0
	}
	count := map[rune]int{}
	for _, r := range runes {
		count[r]++
	}
	var h float64
	for _, c := range count {
		p := float64(c) / n
		h -= p * math.Log2(p)
	}
	return h
}
