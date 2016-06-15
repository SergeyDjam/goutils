package main

import (
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"os"
	"strings"

	cferr "github.com/cloudflare/cfssl/errors"
	"github.com/kr/text"
)

// following two lifted from CFSSL, (replace-regexp "\(.+\): \(.+\),"
// "\2: \1,")

var keyUsage = map[x509.KeyUsage]string{
	x509.KeyUsageDigitalSignature:  "digital signature",
	x509.KeyUsageContentCommitment: "content committment",
	x509.KeyUsageKeyEncipherment:   "key encipherment",
	x509.KeyUsageKeyAgreement:      "key agreement",
	x509.KeyUsageDataEncipherment:  "data encipherment",
	x509.KeyUsageCertSign:          "cert sign",
	x509.KeyUsageCRLSign:           "crl sign",
	x509.KeyUsageEncipherOnly:      "encipher only",
	x509.KeyUsageDecipherOnly:      "decipher only",
}

var extKeyUsages = map[x509.ExtKeyUsage]string{
	x509.ExtKeyUsageAny:                        "any",
	x509.ExtKeyUsageServerAuth:                 "server auth",
	x509.ExtKeyUsageClientAuth:                 "client auth",
	x509.ExtKeyUsageCodeSigning:                "code signing",
	x509.ExtKeyUsageEmailProtection:            "s/mime",
	x509.ExtKeyUsageIPSECEndSystem:             "ipsec end system",
	x509.ExtKeyUsageIPSECTunnel:                "ipsec tunnel",
	x509.ExtKeyUsageIPSECUser:                  "ipsec user",
	x509.ExtKeyUsageTimeStamping:               "timestamping",
	x509.ExtKeyUsageOCSPSigning:                "ocsp signing",
	x509.ExtKeyUsageMicrosoftServerGatedCrypto: "microsoft sgc",
	x509.ExtKeyUsageNetscapeServerGatedCrypto:  "netscape sgc",
}

func pubKeyAlgo(a x509.PublicKeyAlgorithm) string {
	switch a {
	case x509.RSA:
		return "RSA"
	case x509.ECDSA:
		return "ECDSA"
	case x509.DSA:
		return "DSA"
	default:
		return "unknown public key algorithm"
	}
}

func sigAlgoPK(a x509.SignatureAlgorithm) string {
	switch a {

	case x509.MD2WithRSA, x509.MD5WithRSA, x509.SHA1WithRSA, x509.SHA256WithRSA, x509.SHA384WithRSA, x509.SHA512WithRSA:
		return "RSA"
	case x509.ECDSAWithSHA1, x509.ECDSAWithSHA256, x509.ECDSAWithSHA384, x509.ECDSAWithSHA512:
		return "ECDSA"
	case x509.DSAWithSHA1, x509.DSAWithSHA256:
		return "DSA"
	default:
		return "unknown public key algorithm"
	}
}

func sigAlgoHash(a x509.SignatureAlgorithm) string {
	switch a {
	case x509.MD2WithRSA:
		return "MD2"
	case x509.MD5WithRSA:
		return "MD5"
	case x509.SHA1WithRSA, x509.ECDSAWithSHA1, x509.DSAWithSHA1:
		return "SHA1"
	case x509.SHA256WithRSA, x509.ECDSAWithSHA256, x509.DSAWithSHA256:
		return "SHA256"
	case x509.SHA384WithRSA, x509.ECDSAWithSHA384:
		return "SHA384"
	case x509.SHA512WithRSA, x509.ECDSAWithSHA512:
		return "SHA512"
	default:
		return "unknown hash algorithm"
	}
}

// TranslateCFSSLError turns a CFSSL error into a more readable string.
func TranslateCFSSLError(err error) error {
	if err == nil {
		return nil
	}

	// printing errors as json is terrible
	if cfsslError, ok := err.(*cferr.Error); ok {
		err = errors.New(cfsslError.Message)
	}
	return err
}

// Warnx displays a formatted error message to standard error, à la
// warnx(3).
func Warnx(format string, a ...interface{}) (int, error) {
	format += "\n"
	return fmt.Fprintf(os.Stderr, format, a...)
}

// Warn displays a formatted error message to standard output,
// appending the error string, à la warn(3).
func Warn(err error, format string, a ...interface{}) (int, error) {
	format += ": %v\n"
	a = append(a, err)
	return fmt.Fprintf(os.Stderr, format, a...)
}

const maxLine = 78

func makeIndent(n int) string {
	s := "    "
	for i := 0; i < n; i++ {
		s += "        "
	}
	return s
}

func indentLen(n int) int {
	return 4 + (8 * n)
}

// this isn't real efficient, but that's not a problem here
func wrap(s string, indent int) string {
	if indent > 3 {
		indent = 3
	}

	wrapped := text.Wrap(s, maxLine)
	lines := strings.SplitN(wrapped, "\n", 2)
	if len(lines) == 1 {
		return lines[0]
	}

	if (maxLine - indentLen(indent)) <= 0 {
		panic("too much indentation")
	}

	rest := strings.Join(lines[1:], " ")
	wrapped = text.Wrap(rest, maxLine-indentLen(indent))
	return lines[0] + "\n" + text.Indent(wrapped, makeIndent(indent))
}

func dumpHex(in []byte) string {
	var s string
	for i := range in {
		s += fmt.Sprintf("%02X:", in[i])
	}

	return strings.Trim(s, ":")
}

func certPublic(cert *x509.Certificate) string {
	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		return fmt.Sprintf("RSA-%d", pub.N.BitLen())
	case *ecdsa.PublicKey:
		switch pub.Curve {
		case elliptic.P256():
			return "ECDSA-prime256v1"
		case elliptic.P384():
			return "ECDSA-secp384r1"
		case elliptic.P521():
			return "ECDSA-secp521r1"
		default:
			return "ECDSA (unknown curve)"
		}
	case *dsa.PublicKey:
		return "DSA"
	default:
		return "Unknown"
	}
}

func displayName(name pkix.Name) string {
	var ns []string

	if name.CommonName != "" {
		ns = append(ns, name.CommonName)
	}

	for i := range name.Country {
		ns = append(ns, fmt.Sprintf("C=%s", name.Country[i]))
	}

	for i := range name.Organization {
		ns = append(ns, fmt.Sprintf("O=%s", name.Organization[i]))
	}

	for i := range name.OrganizationalUnit {
		ns = append(ns, fmt.Sprintf("OU=%s", name.OrganizationalUnit[i]))
	}

	for i := range name.Locality {
		ns = append(ns, fmt.Sprintf("L=%s", name.Locality[i]))
	}

	for i := range name.Province {
		ns = append(ns, fmt.Sprintf("ST=%s", name.Province[i]))
	}

	if len(ns) > 0 {
		return "/" + strings.Join(ns, "/")
	}

	return "*** no subject information ***"
}

func keyUsages(ku x509.KeyUsage) string {
	var uses []string

	for u, s := range keyUsage {
		if (ku & u) != 0 {
			uses = append(uses, s)
		}
	}

	return strings.Join(uses, ", ")
}

func extUsage(ext []x509.ExtKeyUsage) string {
	ns := make([]string, 0, len(ext))
	for i := range ext {
		ns = append(ns, extKeyUsages[ext[i]])
	}

	return strings.Join(ns, ", ")
}

func showBasicConstraints(cert *x509.Certificate) {
	fmt.Printf("\tBasic constraints: ")
	if cert.BasicConstraintsValid {
		fmt.Printf("valid")
	} else {
		fmt.Printf("invalid")
	}

	if cert.IsCA {
		fmt.Printf(", is a CA certificate")
	}

	if (cert.MaxPathLen == 0 && cert.MaxPathLenZero) || (cert.MaxPathLen > 0) {
		fmt.Printf(", max path length %d", cert.MaxPathLen)
	}

	fmt.Printf("\n")
}

const oneTrueDateFormat = "2006-01-02T15:04:05-0700"

var dateFormat string

func wrapPrint(text string, indent int) {
	tabs := ""
	for i := 0; i < indent; i++ {
		tabs += "\t"
	}

	fmt.Printf(tabs+"%s\n", wrap(text, indent))
}

func displayCert(cert *x509.Certificate) {
	fmt.Println("CERTIFICATE")
	fmt.Println(wrap("Subject: "+displayName(cert.Subject), 0))
	fmt.Println(wrap("Issuer: "+displayName(cert.Issuer), 0))
	fmt.Printf("\tSignature algorithm: %s / %s\n", sigAlgoPK(cert.SignatureAlgorithm),
		sigAlgoHash(cert.SignatureAlgorithm))
	fmt.Println("Details:")
	wrapPrint("Public key: "+certPublic(cert), 1)
	fmt.Printf("\tSerial number: %s\n", cert.SerialNumber)

	if len(cert.AuthorityKeyId) > 0 {
		fmt.Printf("\t%s\n", wrap("AKI: "+dumpHex(cert.AuthorityKeyId), 1))
	}
	if len(cert.SubjectKeyId) > 0 {
		fmt.Printf("\t%s\n", wrap("SKI: "+dumpHex(cert.SubjectKeyId), 1))
	}

	wrapPrint("Valid from: "+cert.NotBefore.Format(dateFormat), 1)
	fmt.Printf("\t     until: %s\n", cert.NotAfter.Format(dateFormat))
	fmt.Printf("\tKey usages: %s\n", keyUsages(cert.KeyUsage))

	if len(cert.ExtKeyUsage) > 0 {
		fmt.Printf("\tExtended usages: %s\n", extUsage(cert.ExtKeyUsage))
	}

	showBasicConstraints(cert)

	validNames := make([]string, 0, len(cert.DNSNames)+len(cert.EmailAddresses)+len(cert.IPAddresses))
	for i := range cert.DNSNames {
		validNames = append(validNames, "dns:"+cert.DNSNames[i])
	}

	for i := range cert.EmailAddresses {
		validNames = append(validNames, "email:"+cert.EmailAddresses[i])
	}

	for i := range cert.IPAddresses {
		validNames = append(validNames, "ip:"+cert.IPAddresses[i].String())
	}

	sans := fmt.Sprintf("SANs (%d): %s\n", len(validNames), strings.Join(validNames, ", "))
	wrapPrint(sans, 1)

	l := len(cert.IssuingCertificateURL)
	if l != 0 {
		var aia string
		if l == 1 {
			aia = "AIA"
		} else {
			aia = "AIAs"
		}
		wrapPrint(fmt.Sprintf("%d %s:", l, aia), 1)
		for _, url := range cert.IssuingCertificateURL {
			wrapPrint(url, 2)
		}
	}
}
