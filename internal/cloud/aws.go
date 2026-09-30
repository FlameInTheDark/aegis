// Package cloud implements the AWS account connector (F10 first slice):
// a read-only EC2 DescribeInstances sweep that lands instances in a chosen
// site as ordinary assets, correlated by instance id (strong) and private
// IP (weak), with public addresses setting exposure on creation. AWS SDKs
// are deliberately avoided — one GET endpoint, SigV4 signing and an XML
// decode are all the slice needs.
package cloud

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

// Instance is one EC2 instance flattened for the asset pipeline.
type Instance struct {
	InstanceID  string
	State       string
	PrivateIP   string
	PublicIP    string
	Name        string // tag "Name"
	InstanceTyp string
}

// describeInstancesResponse is the XML subset of DescribeInstances.
type describeInstancesResponse struct {
	XMLName        xml.Name `xml:"DescribeInstancesResponse"`
	ReservationSet []struct {
		InstancesSet []struct {
			InstanceID   string `xml:"instanceId"`
			InstanceType string `xml:"instanceType"`
			PrivateIP    string `xml:"privateIpAddress"`
			PublicIP     string `xml:"ipAddress"`
			State        struct {
				Name string `xml:"name"`
			} `xml:"instanceState"`
			TagSet []struct {
				Key   string `xml:"key"`
				Value string `xml:"value"`
			} `xml:"tagSet>item"`
		} `xml:"instancesSet>item"`
	} `xml:"reservationSet>item"`
	NextToken string `xml:"nextToken"`
}

// ParseInstancesXML decodes one DescribeInstances response body.
func ParseInstancesXML(data []byte) (instances []Instance, nextToken string, err error) {
	var resp describeInstancesResponse
	if err := xml.Unmarshal(data, &resp); err != nil {
		return nil, "", fmt.Errorf("ec2 xml: %w", err)
	}
	for _, r := range resp.ReservationSet {
		for _, i := range r.InstancesSet {
			inst := Instance{
				InstanceID:  i.InstanceID,
				State:       i.State.Name,
				PrivateIP:   i.PrivateIP,
				PublicIP:    i.PublicIP,
				InstanceTyp: i.InstanceType,
			}
			for _, t := range i.TagSet {
				if t.Key == "Name" {
					inst.Name = t.Value
					break
				}
			}
			instances = append(instances, inst)
		}
	}
	return instances, resp.NextToken, nil
}

// Signer computes AWS Signature Version 4. Used directly so the service has
// zero AWS dependencies and stays testable against the documented vectors.
type Signer struct {
	AccessKey string
	SecretKey string
	Region    string
	Service   string
	Now       func() time.Time
}

// canonicalQuery encodes query params the SigV4 way: sorted by key, values
// RFC 3986 percent-encoded.
func canonicalQuery(q url.Values) string {
	keys := make([]string, 0, len(q))
	for k := range q {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		vals := q[k]
		sort.Strings(vals)
		for _, v := range vals {
			if b.Len() > 0 {
				b.WriteString("&")
			}
			b.WriteString(awsURIEncode(k, true))
			b.WriteString("=")
			b.WriteString(awsURIEncode(v, true))
		}
	}
	return b.String()
}

// awsURIEncode percent-encodes per RFC 3986 with AWS's exception that
// unreserved characters are not encoded and '/' is kept for paths.
func awsURIEncode(s string, isQueryValue bool) string {
	const hexChars = "0123456789ABCDEF"
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		ch := s[i]
		if (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') ||
			ch == '-' || ch == '.' || ch == '_' || ch == '~' {
			b.WriteByte(ch)
		} else if ch == '/' && !isQueryValue {
			b.WriteByte('/')
		} else {
			b.WriteByte('%')
			b.WriteByte(hexChars[ch>>4])
			b.WriteByte(hexChars[ch&0xf])
		}
	}
	return b.String()
}

// Sign computes the Authorization header value for the request. Empty
// payload is assumed (all current callers are GETs); extraHeaders folds
// additional signed headers into the canonical request (sorted there).
func (s *Signer) Sign(method, host, path, rawQuery string, extraHeaders map[string]string) (authorization, amzDate string) {
	now := s.Now()
	if now.IsZero() {
		now = time.Now().UTC()
	}
	amzDate = now.UTC().Format("20060102T150405Z")
	dateShort := amzDate[:8]
	emptyHash := sha256.Sum256(nil)
	payloadHash := hex.EncodeToString(emptyHash[:])

	headers := map[string]string{"host": host, "x-amz-date": amzDate}
	for k, v := range extraHeaders {
		headers[strings.ToLower(k)] = strings.TrimSpace(v)
	}
	names := make([]string, 0, len(headers))
	for k := range headers {
		names = append(names, k)
	}
	sort.Strings(names)
	var canonicalHeaders strings.Builder
	for _, k := range names {
		canonicalHeaders.WriteString(k + ":" + headers[k] + "\n")
	}
	signedHeaders := strings.Join(names, ";")

	canonicalRequest := strings.Join([]string{
		method,
		path,
		rawQuery,
		canonicalHeaders.String(),
		signedHeaders,
		payloadHash,
	}, "\n")
	crSum := sha256.Sum256([]byte(canonicalRequest))
	canonicalRequestHash := hex.EncodeToString(crSum[:])

	scope := strings.Join([]string{dateShort, s.Region, s.Service, "aws4_request"}, "/")
	stringToSign := strings.Join([]string{
		"AWS4-HMAC-SHA256",
		amzDate,
		scope,
		canonicalRequestHash,
	}, "\n")

	kDate := hmacSHA256([]byte("AWS4"+s.SecretKey), dateShort)
	kRegion := hmacSHA256(kDate, s.Region)
	kService := hmacSHA256(kRegion, s.Service)
	kSigning := hmacSHA256(kService, "aws4_request")
	signature := hex.EncodeToString(hmacSHA256(kSigning, stringToSign))

	return fmt.Sprintf("AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		s.AccessKey, scope, signedHeaders, signature), amzDate
}
func hmacSHA256(key []byte, data string) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(data))
	return mac.Sum(nil)
}

// EC2Client lists instances of one account.
type EC2Client struct {
	AccessKey string
	SecretKey string
	Region    string
	HTTP      *http.Client
	// EndpointBase overrides the EC2 endpoint (tests).
	EndpointBase string
}

// DescribeInstances pages through the account's instances (bounded pages).
func (c *EC2Client) DescribeInstances(ctx context.Context, maxPages int) ([]Instance, error) {
	if maxPages <= 0 {
		maxPages = 5
	}
	base := c.EndpointBase
	if base == "" {
		base = "https://ec2." + c.Region + ".amazonaws.com/"
	}
	host := strings.TrimPrefix(strings.TrimSuffix(base, "/"), "https://")
	signer := &Signer{AccessKey: c.AccessKey, SecretKey: c.SecretKey, Region: c.Region, Service: "ec2"}
	client := c.HTTP
	if client == nil {
		client = &http.Client{Timeout: 20 * time.Second}
	}
	var out []Instance
	var next string
	for page := 0; page < maxPages; page++ {
		q := url.Values{"Action": {"DescribeInstances"}, "Version": {"2016-11-15"}}
		if next != "" {
			q.Set("NextToken", next)
		}
		rawQuery := canonicalQuery(q)
		authHeader, amzDate := signer.Sign(http.MethodGet, host, "/", rawQuery, nil)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"?"+rawQuery, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", authHeader)
		req.Header.Set("x-amz-date", amzDate)
		resp, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
		resp.Body.Close()
		if err != nil {
			return nil, err
		}
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("ec2 returned status %d: %s", resp.StatusCode, truncate(string(body), 300))
		}
		instances, token, err := ParseInstancesXML(body)
		if err != nil {
			return nil, err
		}
		out = append(out, instances...)
		if token == "" {
			break
		}
		next = token
	}
	return out, nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
