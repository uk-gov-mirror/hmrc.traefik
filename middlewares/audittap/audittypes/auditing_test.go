package audittypes

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"testing"
	"time"

	"strconv"

	"github.com/containous/traefik/middlewares/audittap/types"
	"github.com/stretchr/testify/assert"
)

func TestAppendCommonRequestFields(t *testing.T) {

	types.TheClock = T0

	var ev = &AuditEvent{}
	var req = httptest.NewRequest("POST", "/some/resource?qz=abc", nil)
	req.Header.Set("X-Request-Id", "req321")
	req.Header.Set("True-Client-IP", "101.1.101.1")
	req.Header.Set("True-Client-Port", "5005")
	req.Header.Set("X-Source", "202.2.202.2")
	req.Header.Set("Request-ID", "R123")
	req.Header.Set("Session-ID", "S123")
	req.Header.Set("Akamai-Test-Hdr", "Ak999")

	appendCommonRequestFields(ev, NewRequestContext(req))

	assert.NotEmpty(t, ev.EventID)
	assert.Equal(t, "2001-09-09T01:46:40.000Z", ev.GeneratedAt)
	assert.Equal(t, "1", ev.Version)
	assert.Equal(t, "POST", ev.Method)
	assert.Equal(t, "/some/resource", ev.Path)
	assert.Equal(t, "qz=abc", ev.QueryString)
	assert.Equal(t, "req321", ev.RequestID)
	assert.Equal(t, "101.1.101.1", ev.ClientIP)
	assert.Equal(t, "5005", ev.ClientPort)
	assert.Equal(t, "202.2.202.2", ev.ReceivingIP)
	assert.Equal(t, types.DataMap{"session-id": "S123", "request-id": "R123"}, ev.ClientHeaders)
	assert.Equal(t, types.DataMap{"akamai-test-hdr": "Ak999"}, ev.RequestHeaders)
	assert.Empty(t, ev.ResponseStatus)
	assert.Nil(t, ev.ResponseHeaders)
	assert.Nil(t, ev.ResponsePayload)
}

func TestAppendCommonResponseFields(t *testing.T) {

	var ev = &AuditEvent{}
	var respHeaders = http.Header{}
	respHeaders.Set("Content-Type", "text/plain")
	respHeaders.Set("Some-Hdr-X", "X99")
	respHeaders.Add("Cookie", "a=1; b=2")
	respHeaders.Add("Cookie", "c=3")

	respInfo := types.ResponseInfo{200, 99, nil, 2048}

	returned := appendCommonResponseFields(ev, respHeaders, respInfo)

	expectRespHdrs := types.DataMap{
		"cookie":     []string{"a=1", "b=2", "c=3"},
		"some-hdr-x": "X99",
	}

	assert.Equal(t, strconv.Itoa(respInfo.Status), ev.ResponseStatus)
	assert.Equal(t, types.DataMap{"type": "text/plain"}, ev.ResponsePayload)
	assert.Equal(t, expectRespHdrs, ev.ResponseHeaders)
	assert.Equal(t, types.DataMap{"cookie": []string{"a=1", "b=2", "c=3"}, "content-type": "text/plain", "some-hdr-x": "X99"}, returned)
}

func TestAuditResponseHeaders(t *testing.T) {

	var ev = &AuditEvent{}
	var respHeaders = http.Header{}

	// hop-by-hop headers should be retained
	respHeaders.Set("Keep-Alive", "true")
	respHeaders.Set("Connection", "1")
	respHeaders.Set("Proxy-Authenticate", "1")
	respHeaders.Set("Proxy-Authorization", "1")
	respHeaders.Set("TE", "1")
	respHeaders.Set("Trailers", "1")
	respHeaders.Set("Transfer-Encoding", "1")
	respHeaders.Set("Upgrade", "1")

	// other headers should be retained
	respHeaders.Set("Content-Length", "123")
	respHeaders.Set("Request-ID", "abc123")
	respHeaders.Add("Cookie", "a=1; b=2")
	respHeaders.Add("Cookie", "c=3")

	// content-type should be set under responsePayload
	respHeaders.Add("Content-Type", "application/json")

	appendCommonResponseFields(ev, respHeaders, types.ResponseInfo{200, 99, nil, 2048})

	expectRespHdrs := types.DataMap{
		"trailers":            "1",
		"proxy-authenticate":  "1",
		"cookie":              []string{"a=1", "b=2", "c=3"},
		"te":                  "1",
		"request-id":          "abc123",
		"content-length":      "123",
		"transfer-encoding":   "1",
		"proxy-authorization": "1",
		"connection":          "1",
		"upgrade":             "1",
		"keep-alive":          "true"}

	assert.Equal(t, types.DataMap{"type": "application/json"}, ev.ResponsePayload)
	assert.Equal(t, expectRespHdrs, ev.ResponseHeaders)
}

func TestRequestContentsOmittedWhenTooLong(t *testing.T) {
	max := 20
	ev := AuditEvent{RequestPayload: types.DataMap{}}
	constraints := AuditConstraints{MaxAuditLength: 1000, MaxPayloadContentsLength: int64(max)}
	ev.RequestPayload[keyPayloadContents] = types.DataMap{"Key1": "MoreThan20Bytes"}
	ev.RequestPayload[keyPayloadLength] = max + 1
	enforcePrecedentConstraints(&ev, constraints)
	assert.Nil(t, ev.RequestPayload[keyPayloadContents])
}

func TestResponseContentsOmittedWhenTooLong(t *testing.T) {
	max := 20
	ev := AuditEvent{ResponsePayload: types.DataMap{}}
	constraints := AuditConstraints{MaxAuditLength: 1000, MaxPayloadContentsLength: int64(max)}
	ev.ResponsePayload[keyPayloadContents] = types.DataMap{"Key1": "MoreThan20Bytes"}
	ev.ResponsePayload[keyPayloadLength] = max + 1
	enforcePrecedentConstraints(&ev, constraints)
	assert.Nil(t, ev.ResponsePayload[keyPayloadContents])
}

func TestResponseContentsOmittedWhenResponseAndRequestTooLong(t *testing.T) {
	// CDP-1377 we evaluate the size of the combined (request+response) payload and remove if exceeds max payliad contents length
	requestPayload := types.DataMap{"Key1": "AllowedRequestSize"}
	max := 40
	ev := AuditEvent{RequestPayload: types.DataMap{}, ResponsePayload: types.DataMap{}}
	constraints := AuditConstraints{MaxAuditLength: 1000, MaxPayloadContentsLength: int64(max)}
	ev.RequestPayload[keyPayloadContents] = requestPayload
	ev.RequestPayload[keyPayloadLength] = max / 2
	ev.ResponsePayload[keyPayloadContents] = types.DataMap{"Key1": "DisallowedResponseSize"}
	ev.ResponsePayload[keyPayloadLength] = (max / 2) + 1
	enforcePrecedentConstraints(&ev, constraints)
	assert.Nil(t, ev.ResponsePayload[keyPayloadContents])
	assert.Nil(t, ev.RequestPayload[keyPayloadContents])
}

// CDP-1377 if we only have a request payload is this retained
func TestRequestContentsRetained(t *testing.T) {
	max := 1000
	contents := types.DataMap{"Key1": "MoreThan20Bytes"}
	ev := RATEAuditEvent{}
	ev.AuditEvent = AuditEvent{RequestPayload: types.DataMap{}}
	constraints := AuditConstraints{MaxAuditLength: 1000, MaxPayloadContentsLength: int64(max)}
	ev.RequestPayload[keyPayloadContents] = contents
	ev.RequestPayload[keyPayloadLength] = max - 1
	enforcePrecedentConstraints(&ev.AuditEvent, constraints)

	assert.Equal(t, contents, ev.RequestPayload[keyPayloadContents])
	assert.Nil(t, ev.ResponsePayload[keyPayloadContents])
}

// CDP-1377 if we only have a response payload is this retained
func TestResponseContentsRetained(t *testing.T) {
	max := 1000
	contents := types.DataMap{"Key1": "MoreThan20Bytes"}
	ev := RATEAuditEvent{}
	ev.AuditEvent = AuditEvent{RequestPayload: types.DataMap{}, ResponsePayload: types.DataMap{}}
	constraints := AuditConstraints{MaxAuditLength: 1000, MaxPayloadContentsLength: int64(max)}
	ev.ResponsePayload[keyPayloadContents] = contents
	ev.ResponsePayload[keyPayloadLength] = max - 1
	enforcePrecedentConstraints(&ev.AuditEvent, constraints)

	assert.Equal(t, contents, ev.ResponsePayload[keyPayloadContents])
	assert.Nil(t, ev.RequestPayload[keyPayloadContents])
}

func TestResponseContentsRetained1M(t *testing.T) {
	contents := types.DataMap{"Key1": "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Proin quis viverra nulla. Nunc lacinia eget ante in lobortis. Cras sed quam egestas nibh tristique eleifend. Aenean eleifend quam sapien, eu convallis ante blandit et. Cras accumsan mi id leo consequat rhoncus. Donec dapibus leo nec augue commodo, varius posuere purus dignissim. Sed placerat nulla non vestibulum semper. Fusce leo mauris, feugiat nec mauris in, blandit commodo tellus. Mauris in lobortis turpis. Proin at ligula eget odio elementum dignissim eu vel mauris. Donec dui tortor, dapibus ac purus vel, sagittis tincidunt metus. Suspendisse nec dictum tellus.Nunc vel dolor eu neque tristique condimentum. Vivamus quis mauris urna. Proin tortor quam, pretium ac pellentesque accumsan, sagittis quis dui. Maecenas sit amet viverra est, et fermentum lacus. Aliquam eu eleifend metus. Nulla facilisi. Nulla auctor turpis vitae eros dapibus, ac fringilla quam tincidunt. Morbi efficitur mauris eu sagittis tempus. Aenean varius placerat nisi, id blandit risus ullamcorper in. Pellentesque libero lorem, tempus eget semper vel, rhoncus posuere erat. Sed tincidunt eros in lorem cursus viverra. Quisque a tristique mi. Orci varius natoque penatibus et magnis dis parturient montes, nascetur ridiculus mus. Duis non velit orci.Pellentesque a auctor turpis, quis condimentum justo. Aliquam ut consequat felis. Quisque gravida accumsan lorem ac congue. Donec ultrices dolor in efficitur ultricies. Nulla ligula libero, venenatis in velit vel, aliquet vestibulum orci. Maecenas id mauris ligula. Suspendisse malesuada erat nec nulla semper, a dictum odio porttitor. Mauris id posuere lorem, ut congue augue. Nam porttitor risus eget dui ultrices ullamcorper nec nec augue. Proin vestibulum quam nisi, at tincidunt purus commodo non. Maecenas pretium augue non luctus iaculis. Suspendisse condimentum, arcu vel rhoncus laoreet, est metus efficitur justo, non blandit nibh neque sed purus. Sed interdum in nunc ut tincidunt. Suspendisse morbi."}

	max := len(contents)
	ev := RATEAuditEvent{}
	ev.AuditEvent = AuditEvent{RequestPayload: types.DataMap{}, ResponsePayload: types.DataMap{}}
	constraints := AuditConstraints{MaxAuditLength: int64(max*2), MaxPayloadContentsLength: int64(max*2)}

	ev.RequestPayload[keyPayloadLength] = max
	ev.RequestPayload[keyPayloadContents] = contents

	ev.ResponsePayload[keyPayloadLength] = max
	ev.ResponsePayload[keyPayloadContents] = contents

	enforcePrecedentConstraints(&ev.AuditEvent, constraints)

	assert.NotEmpty(t, ev.RequestPayload[keyPayloadContents])
	assert.NotEmpty(t, ev.ResponsePayload[keyPayloadContents])
	assert.Equal(t, contents, ev.ResponsePayload[keyPayloadContents])
}

func TestAuditObfuscateUrlEncoded(t *testing.T) {
	obs := AuditObfuscation{MaskValue: "@++@", MaskFields: []string{"x1"}}

	masked, err := obs.ObfuscateURLEncoded([]byte("start=s1&x1=kkdw09dkwad&def=d1&x1=wdoueqoi2ej&end=e1"))
	assert.NoError(t, err)
	assert.Equal(t, "start=s1&x1=@++@&def=d1&x1=@++@&end=e1", string(masked))

	masked, err = obs.ObfuscateURLEncoded([]byte("x1=aefaef&d1=dere%20e&x1=wdawdwwd&d2=ziefjef&x1=brerber"))
	assert.NoError(t, err)
	assert.Equal(t, "x1=@++@&d1=dere%20e&x1=@++@&d2=ziefjef&x1=@++@", string(masked))
}

func TestAuditObfuscateJSON(t *testing.T) {

	obs := AuditObfuscation{MaskValue: "@++@", MaskFields: []string{"x1", "x2", "my_secret"}}

	j1 := `{"x1":"blah"}`
	masked, err := obs.ObfuscateJSON([]byte(j1))
	assert.NoError(t, err)
	assert.Equal(t, `{"x1": "@++@"}`, string(masked))

	j2 := `{
		"a1": "foo",
		"x1":     "blah",
		"a2": "bar"
	}`
	masked, err = obs.ObfuscateJSON([]byte(j2))
	assert.NoError(t, err)
	assert.Equal(t, `{
		"a1": "foo",
		"x1": "@++@",
		"a2": "bar"
	}`, string(masked))

	j3 := `{"my_secret": "e336a67a-c598-4800-a1af-dcca0aaee3ea", "grant_type": "cred", "x2": "y0tr1pp1ng", "redirect_uri": "http://localhost:8080"}`
	expectedBody := `{"my_secret": "@++@", "grant_type": "cred", "x2": "@++@", "redirect_uri": "http://localhost:8080"}`
	masked, err = obs.ObfuscateJSON([]byte(j3))
	assert.NoError(t, err)
	assert.Equal(t, expectedBody, string(masked))

	j4 := `{"my_secret": "e336a67a-c598-4800-a1af-dcca0aaee3ea", "x2": "hideme", "grant_type": "cred", "x2": "y0tr1pp1ng", "redirect_uri": "http://localhost:8080"}`
	expectedBody = `{"my_secret": "@++@", "x2": "@++@", "grant_type": "cred", "x2": "@++@", "redirect_uri": "http://localhost:8080"}`
	masked, err = obs.ObfuscateJSON([]byte(j4))
	assert.NoError(t, err)
	assert.Equal(t, expectedBody, string(masked))

	j5 := `{ 
		"x2": 
		  "foo"
	}`
	expectedBody = `{ 
		"x2": "@++@"
	}`
	masked, err = obs.ObfuscateJSON([]byte(j5))
	assert.NoError(t, err)
	assert.Equal(t, expectedBody, string(masked))

	j6 := `{ 
		"x2"
		  : "foo"
	}`
	expectedBody = `{ 
		"x2": "@++@"
	}`
	masked, err = obs.ObfuscateJSON([]byte(j6))
	assert.NoError(t, err)
	assert.Equal(t, expectedBody, string(masked))
}

func TestAuditExclusion(t *testing.T) {

	excludes := []*Filter{
		{Source: "Host", Contains: []string{"aaaignorehost1bbb", "hostignore"}},
		{Source: "Path", StartsWith: []string{"/excludeme", "/someotherpath"}},
		{Source: "Hdr1", Contains: []string{"abcdefg", "drv1"}},
		{Source: "Hdr2", Contains: []string{"tauditm"}},
	}

	spec := &AuditSpecification{
		Exclusions: excludes,
	}

	excHost := NewRequestContext(httptest.NewRequest("", "/pathsegment?d=1&e=2", nil))
	excHost.Req.Host = "abchostignoredef.somedomain"
	assert.False(t, ShouldAudit(excHost, spec))

	excPath := NewRequestContext(httptest.NewRequest("", "/excludeme?d=1&e=2", nil))
	assert.False(t, ShouldAudit(excPath, spec))

	req1 := httptest.NewRequest("", "/pathsegment?d=1&e=2", nil)
	req1.Header.Set("Hdr1", "xdrv1z")
	excHdr1 := NewRequestContext(req1)
	assert.False(t, ShouldAudit(excHdr1, spec))

	req2 := httptest.NewRequest("", "/pathsegment?d=1&e=2", nil)
	req2.Header.Set("Hdr2", "don'tauditme")
	excHdr2 := NewRequestContext(req2)
	assert.False(t, ShouldAudit(excHdr2, spec))

	incReq := httptest.NewRequest("", "/includeme?d=1&e=2", nil)
	incReq.Header.Set("Hdr1", "bcdef")
	incHdr1 := NewRequestContext(incReq)
	assert.True(t, ShouldAudit(incHdr1, spec))
}

func TestAuditInclusion(t *testing.T) {

	includes := []*Filter{
		{Source: "Host", Contains: []string{"somehostname", "hostinc"}},
		{Source: "Path", StartsWith: []string{"/includeme", "/someotherpath"}},
		{Source: "Hdr1", Contains: []string{"abcdefg", "drv1"}},
		{Source: "Hdr2", Contains: []string{"auditme"}},
	}

	spec := &AuditSpecification{
		Inclusions: includes,
	}

	incHost := NewRequestContext(httptest.NewRequest("", "/pathsegment?d=1&e=2", nil))
	incHost.Req.Host = "abchostincdef.somedomain"
	assert.True(t, ShouldAudit(incHost, spec))

	incPath := NewRequestContext(httptest.NewRequest("", "/includeme?d=1&e=2", nil))
	assert.True(t, ShouldAudit(incPath, spec))

	req1 := httptest.NewRequest("", "/pathsegment?d=1&e=2", nil)
	req1.Header.Set("Hdr1", "xdrv1z")
	incHdr1 := NewRequestContext(req1)
	assert.True(t, ShouldAudit(incHdr1, spec))

	req2 := httptest.NewRequest("", "/pathsegment?d=1&e=2", nil)
	req2.Header.Set("Hdr2", "auditme")
	incHdr2 := NewRequestContext(req2)
	assert.True(t, ShouldAudit(incHdr2, spec))

	excReq := httptest.NewRequest("", "/excludeme?d=1&e=2", nil)
	excReq.Header.Set("Hdr1", "bcdef")
	excHdr1 := NewRequestContext(excReq)
	assert.False(t, ShouldAudit(excHdr1, spec))
}

func TestShouldCaptureRequestBody(t *testing.T) {

	filters := []*Filter{
		{Source: "Host", Contains: []string{"somehostname", "hostinc"}},
		{Source: "Host", Matches: []*regexp.Regexp{
			regexp.MustCompile(".*\\.random\\.com")}},
	}

	spec := &AuditSpecification{
		RequestBodyCaptures: filters,
	}

	hostinc := NewRequestContext(httptest.NewRequest("", "/pathsegment?d=1&e=2", nil))
	hostinc.Req.Host = "abchostincdef.somedomain"
	assert.True(t, ShouldCaptureRequestBody(hostinc, spec))

}

func TestShouldIgnoreRequestBody(t *testing.T) {

	captures := []*Filter{
		{Source: "Host", Contains: []string{"somehostname", "hostinc"}},
	}
	ignores := []*Filter{
		{Source: "Path", Contains: []string{"ignorepath"}},
	}

	spec := &AuditSpecification{
		RequestBodyCaptures: captures,
		RequestBodyIgnores:  ignores,
	}

	req1 := NewRequestContext(httptest.NewRequest("", "/pathsegment?d=1&e=2", nil))
	req1.Req.Host = "abchostincdef.somedomain"
	assert.True(t, ShouldCaptureRequestBody(req1, spec))

	req2 := NewRequestContext(httptest.NewRequest("", "/aaaignorepathbbb?d=1&e=2", nil))
	req2.Req.Host = "abchostincdef.somedomain"
	assert.False(t, ShouldCaptureRequestBody(req2, spec))
}
func TestSatisfiesFilter(t *testing.T) {
	assert.True(t, filterSatisfies(Filter{Source: "x", StartsWith: []string{"begin"}}, "beginWithThis"))
	assert.True(t, filterSatisfies(Filter{Source: "x", EndsWith: []string{"That"}}, "endWithThat"))
	assert.True(t, filterSatisfies(Filter{Source: "x", Contains: []string{"hasthat"}}, "ithasthatthing"))

	assert.False(t, filterSatisfies(Filter{Source: "x", StartsWith: []string{"abc"}}, "bcd"))
	assert.False(t, filterSatisfies(Filter{Source: "x", EndsWith: []string{"def"}}, "bcd"))
	assert.False(t, filterSatisfies(Filter{Source: "x", Contains: []string{"abcde"}}, "bcd"))
}

func TestShouldSatisfyFilterRegex(t *testing.T) {
	assert.True(t, filterSatisfies(Filter{Source: "x", Matches: []*regexp.Regexp{regexp.MustCompile("^begin.*")}}, "beginWithThis"))
	assert.False(t, filterSatisfies(Filter{Source: "x", Matches: []*regexp.Regexp{regexp.MustCompile("abcde")}}, "abcdx"))
}

func filterSatisfies(f Filter, s string) bool {
	return f.satisfiedBy(s)
}

type fixedClock time.Time

func (c fixedClock) Now() time.Time {
	return time.Time(c)
}

var T0 = fixedClock(time.Unix(1000000000, 0))
