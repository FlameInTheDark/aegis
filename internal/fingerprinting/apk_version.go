// Alpine apk version ordering — a faithful port of apk-tools' version.c
// grammar (as also implemented by knqyf263/go-apk-version), needed by the
// distro advisory plane. The grammar:
//
//	number{.number}...{letter}{_suffix{number}}...{-rN}
//
// with pre-release suffixes alpha/beta/pre/rc (negative weight — a version
// with one is OLDER than the same version without), post-release suffixes
// cvs/svn/git/hg/p (positive), and the -rN package revision compared last.
// Leading-zero numeric components compare by zero count (0.01 < 0.1).
package fingerprinting

import (
	"unicode"
	"unicode/utf8"
)

const (
	apkTokInvalid = iota - 1
	apkTokDigitOrZero
	apkTokDigit
	apkTokLetter
	apkTokSuffix
	apkTokSuffixNo
	apkTokRevNo
	apkTokEnd
)

var apkPreSuffixes = []string{"alpha", "beta", "pre", "rc"}
var apkPostSuffixes = []string{"cvs", "svn", "git", "hg", "p"}

// apkReader mirrors the bufio.Reader semantics the grammar relies on:
// ReadRune/UnreadRune pairing (prev-rune rewind) and Peek that ignores the
// unread state.
type apkReader struct {
	s    string
	r    int // index of the next byte to read
	prev int // index of the previously read rune (-1 = none)
}

func newApkReader(s string) *apkReader { return &apkReader{s: s, prev: -1} }

func (a *apkReader) readRune() (rune, bool) {
	// bufio.ReadRune always reads at the cursor; prev only remembers the
	// rune start for UnreadRune.
	if a.r >= len(a.s) {
		return 0, false
	}
	r, size := utf8.DecodeRuneInString(a.s[a.r:])
	a.prev = a.r
	a.r += size
	return r, true
}

func (a *apkReader) unreadRune() {
	if a.prev >= 0 {
		a.r = a.prev
		a.prev = -1
	}
}

func (a *apkReader) discard(n int) {
	a.prev = -1
	if a.r+n <= len(a.s) {
		a.r += n
	} else {
		a.r = len(a.s)
	}
}

func (a *apkReader) peek(n int) (string, bool) {
	if a.r >= len(a.s) {
		return "", false
	}
	if a.r+n > len(a.s) {
		return a.s[a.r:], true
	}
	return a.s[a.r : a.r+n], true
}

// apkNextToken decides the token type that follows; mirrors
// apk-tools' next_token. The separator itself ('.'/'_'/'-') is consumed
// here; boundary runes (letters, digits) are un-read for getToken.
func (a *apkReader) apkNextToken(tokenType int) int {
	n := apkTokInvalid
	r, ok := a.readRune()
	if !ok {
		return apkTokEnd
	}
	switch {
	case (tokenType == apkTokDigit || tokenType == apkTokDigitOrZero) && unicode.IsLower(r):
		n = apkTokLetter
	case tokenType == apkTokLetter && unicode.IsDigit(r):
		n = apkTokDigit
	case tokenType == apkTokSuffix && unicode.IsDigit(r):
		n = apkTokSuffixNo
	default:
		switch r {
		case '.':
			n = apkTokDigitOrZero
		case '_':
			n = apkTokSuffix
		case '-':
			_, ok := a.readRune()
			if !ok {
				n = apkTokInvalid
			} else {
				n = apkTokRevNo
			}
		}
	}
	if n == apkTokEnd || n == apkTokLetter || n == apkTokDigit || n == apkTokSuffixNo {
		a.unreadRune()
	}
	if n < tokenType {
		switch {
		case n == apkTokDigitOrZero && tokenType == apkTokDigit:
			return n
		case n == apkTokSuffix && tokenType == apkTokSuffixNo:
			return n
		case n == apkTokDigit && tokenType == apkTokLetter:
			return n
		default:
			return apkTokInvalid
		}
	}
	return n
}

// apkGetToken consumes one token and returns its numeric value plus the
// token type that follows.
func (a *apkReader) apkGetToken(tokenType int) (int, int) {
	var value int
	var r rune
	r, _ = a.readRune()
	nt := apkTokInvalid

	switch tokenType {
	case apkTokDigitOrZero:
		if r == '0' {
			// Leading-zero digits: each extra zero counts DOWN, so
			// 0.01 < 0.1 (apk-tools special case).
			for {
				value--
				r2, ok := a.readRune()
				if !ok {
					break
				}
				if r2 != '0' {
					a.unreadRune()
					break
				}
			}
			nt = apkTokDigit
		} else {
			value = a.digitRun(r)
		}
	case apkTokDigit, apkTokSuffixNo, apkTokRevNo:
		value = a.digitRun(r)
	case apkTokLetter:
		value = int(r)
	case apkTokSuffix:
		a.unreadRune()
		// The value starts at zero (not negative!): a pre-suffix match
		// always writes a negative weight (i-len(pre) < 0), and only a
		// NO-match falls through to the post-suffix scan — this mirrors
		// apk-tools' `if (value != 0) break` exactly.
		var matched bool
		for i, sfx := range apkPreSuffixes {
			if b, _ := a.peek(len(sfx)); b == sfx {
				value = i - len(apkPreSuffixes)
				a.discard(len(sfx))
				matched = true
				break
			}
		}
		if matched {
			break
		}
		value = -1
		for i, sfx := range apkPostSuffixes {
			if b, _ := a.peek(len(sfx)); b == sfx {
				value = i
				a.discard(len(sfx))
				break
			}
		}
		if value >= 0 {
			break
		}
		return -1, apkTokInvalid
	default:
		return -1, apkTokInvalid
	}

	if _, ok := a.peek(1); !ok {
		tokenType = apkTokEnd
	} else if nt != apkTokInvalid {
		tokenType = nt
	} else {
		tokenType = a.apkNextToken(tokenType)
	}
	return value, tokenType
}

// digitRun consumes a run of ASCII digits starting with the rune already
// read, then un-reads the terminator.
func (a *apkReader) digitRun(first rune) int {
	value := 0
	r := first
	for {
		if !unicode.IsDigit(r) {
			a.unreadRune()
			return value
		}
		value = value*10 + int(r-'0')
		var ok bool
		r, ok = a.readRune()
		if !ok {
			return value
		}
	}
}

// apkCompare orders two versions under the Alpine apk grammar.
// Returns -1 (a < b), 0 (equal), 1 (a > b). Invalid versions never
// compare equal to valid ones (invalid sorts first, mirroring apk-tools'
// invalid-token ordering).
func apkCompare(a, b string) int {
	ra := newApkReader(a)
	rb := newApkReader(b)

	at, bt := apkTokDigit, apkTokDigit
	var av, bv int
	for at == bt && at != apkTokEnd && at != apkTokInvalid && av == bv {
		av, at = ra.apkGetToken(at)
		bv, bt = rb.apkGetToken(bt)
	}

	if av < bv {
		return -1
	} else if av > bv {
		return 1
	}
	if at == bt {
		return 0
	}
	// Equal components so far: the longer version wins unless its extra
	// part is a pre-release suffix (1.2_alpha < 1.2).
	if at == apkTokSuffix {
		if v, _ := ra.apkGetToken(at); v < 0 {
			return -1
		}
	}
	if bt == apkTokSuffix {
		if v, _ := rb.apkGetToken(bt); v < 0 {
			return 1
		}
	}
	if at > bt {
		return -1
	} else if at < bt {
		return 1
	}
	return 0
}
