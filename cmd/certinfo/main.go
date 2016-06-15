package main

import (
	"crypto/x509"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"strings"

	"github.com/cloudflare/cfssl/helpers"
	"github.com/kisom/goutils/die"
	"github.com/kisom/goutils/lib"
)

func usage(w io.Writer) {
	fmt.Fprintf(w, `Usage: certinfo [-aiq] bundle identifier terms

	Flags:
		-a	By default, certinfo combines search terms with 
			AND; this flag specifies that OR should be used.
		-i	Search should be case-insensitive.
		-q	Don't produce any output; the error code is used
			to indicate matches.

	certinfo returns exit code 0 if a match was made, 1 if there was
	an error, and 2 if no matches were found.

	bundle should be a PEM-encoded bundle of certificates.

	Supported identifiers:
		+ ski



`, lib.ProgName())
}

func init() {
	flag.Usage = func() { usage(os.Stderr) }
}

var opts struct {
	any   bool
	cs    bool
	quiet bool
}

func findSKI(certs []*x509.Certificate, skis []string) (results []*x509.Certificate) {
	for i := range skis {
		skis[i] = strings.ToUpper(skis[i])

		for _, cert := range certs {
			ski := dumpHex(cert.SubjectKeyId)
			if strings.Contains(ski, skis[i]) {
				results = append(results, cert)
			}
		}
	}

	return results
}

func normalise(term string) string {
	if opts.cs {
		return strings.ToLower(term)
	}
	return term
}

func hasSAN(hosts []string, term string) bool {
	term = normalise(term)
	for _, host := range hosts {
		if strings.Contains(normalise(host), term) {
			return true
		}
	}
	return false
}

func findSAN(certs []*x509.Certificate, terms []string) []*x509.Certificate {
	if opts.any {
		return findAnySAN(certs, terms)
	}
	return findAllSAN(certs, terms)
}

func findAnySAN(certs []*x509.Certificate, terms []string) (results []*x509.Certificate) {
	for _, cert := range certs {
		var found bool
		for _, term := range terms {
			if hasSAN(cert.DNSNames, term) {
				found = true
			}
		}

		if found {
			results = append(results, cert)
		}
	}

	return results
}

func findAllSAN(certs []*x509.Certificate, terms []string) (results []*x509.Certificate) {
	for _, cert := range certs {
		match := true
		if len(cert.DNSNames) == 0 {
			continue
		}

		for _, term := range terms {
			match = match && hasSAN(cert.DNSNames, term)
		}

		if match {
			results = append(results, cert)
		}
	}

	return results
}

func main() {
	flag.BoolVar(&opts.any, "a", false, "search for any of the terms")
	flag.BoolVar(&opts.cs, "i", false, "case-insensitive search")
	flag.BoolVar(&opts.quiet, "q", false, "quiet mode")
	flag.Parse()

	if flag.NArg() < 3 {
		usage(os.Stderr)
		os.Exit(lib.ExitFailure)
	}

	bundle := flag.Arg(0)
	ident := flag.Arg(1)
	terms := flag.Args()[2:]

	bundleData, err := ioutil.ReadFile(bundle)
	die.If(err)

	certs, err := helpers.ParseCertificatesPEM(bundleData)
	die.If(err)

	var results []*x509.Certificate

	switch ident {
	case "ski":
		if len(terms) > 1 && !opts.any {
			lib.Errx(lib.ExitFailure, "Searching multiple SKIs is only supported with the -a flag.")
		}

		results = findSKI(certs, terms)
	case "san":
		results = findSAN(certs, terms)
	default:
		lib.Errx(lib.ExitFailure, "Unknown identifier %s: maybe this isn't implemented yet?", ident)
	}

	if len(results) > 0 {
		if !opts.quiet {
			for _, cert := range results {
				displayCert(cert)
			}
		}

		os.Exit(0)
	} else {
		os.Exit(2)
	}
}
