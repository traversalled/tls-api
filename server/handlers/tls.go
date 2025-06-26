package handlers

import (
	"bytes"
	"fmt"
	http "github.com/bogdanfinn/fhttp"
	tlsclient "github.com/bogdanfinn/tls-client"
	"github.com/bogdanfinn/tls-client/profiles"
	"github.com/brianxor/tls-api/internal/utils"
	"github.com/gofiber/fiber/v3"
	"io"
	"math/rand"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"
	//srt "github.com/juzeon/spoofed-round-tripper" Srtill to asd later for akamai spoofing ect
)

var (
	methodsWithoutRequestBody = []string{
		http.MethodGet,
		http.MethodHead,
		http.MethodOptions,
		http.MethodTrace,
	}

	supportedReqMethods = append(methodsWithoutRequestBody,
		http.MethodPost,
		http.MethodPut,
		http.MethodPatch,
		http.MethodDelete,
	)
)

const (
	tlsUrlHeaderKey                      = "x-tls-url"
	tlsMethodHeaderKey                   = "x-tls-method"
	tlsProxyHeaderKey                    = "x-tls-proxy"
	tlsProfileHeaderKey                  = "x-tls-profile"
	tlsClientTimeoutHeaderKey            = "x-tls-client-timeout"
	tlsFollowRedirectsHeaderKey          = "x-tls-follow-redirects"
	tlsForceHttp1HeaderKey               = "x-tls-force-http1"
	tlsInsecureSkipVerifyHeaderKey       = "x-tls-insecure-skip-verify"
	tlsHeaderOrderHeaderKey              = "x-tls-header-order"
	tlsPseudoHeaderOrderHeaderKey        = "x-tls-pseudo-header-order"
	tlsWithRandomExtensionOrderHeaderKey = "x-tls-with-random-extension-order"
	tlsShuffleHeadersKey                 = "x-tls-shuffle" //Shuffle of header packet itself not Just spoofing the header order
)

func HandleTlsForwardRoute(ctx fiber.Ctx) error {
	tlsConfig, err := extractTlsData(ctx)

	if err != nil {
		return handleErrorResponse(ctx, fmt.Sprintf("error while extracting tls data: %s", err))
	}

	reqResponse, err := doRequest(tlsConfig)

	if err != nil {
		return handleErrorResponse(ctx, "error while doing request")
	}

	setResponseHeaders(ctx, reqResponse)
	setResponseCookies(ctx, reqResponse)

	return ctx.Status(reqResponse.responseCode).Send(reqResponse.responseBody)
}

type requestResponse struct {
	responseBody    []byte
	responseCode    int
	responseHeaders map[string]string
	responseCookies []*http.Cookie
}

func doRequest(tlsData *tlsData) (*requestResponse, error) {
	req, err := createRequest(tlsData)
	if err != nil {
		return nil, err
	}

	httpClient, err := buildTlsClient(tlsData)
	if err != nil {
		return nil, err
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}

	body, err := utils.DecompressBody(resp)
	if err != nil {
		return nil, err
	}

	return &requestResponse{
		responseBody:    body,
		responseCode:    resp.StatusCode,
		responseHeaders: getResponseHeaders(resp),
		responseCookies: resp.Cookies(),
	}, nil
}

func createRequest(tlsData *tlsData) (*http.Request, error) {
	var requestBodyReader io.Reader
	if tlsData.requestMethod != http.MethodGet && len(tlsData.requestBody) > 0 {
		requestBodyReader = bytes.NewReader(tlsData.requestBody)
	}
	req, err := http.NewRequest(tlsData.requestMethod, tlsData.requestUrl, requestBodyReader)
	if err != nil {
		return nil, err
	}
	setRequestHeaders(tlsData, req)
	return req, nil
}

func buildTlsClient(tlsData *tlsData) (tlsclient.HttpClient, error) {
	tlsOptions := []tlsclient.HttpClientOption{
		tlsclient.WithTimeoutSeconds(tlsData.tlsClientTimeout),
		tlsclient.WithClientProfile(tlsData.tlsClientProfile),
		tlsclient.WithTransportOptions(&tlsclient.TransportOptions{
			DisableCompression: true,
		}),
	}
	if !tlsData.tlsFollowRedirects {
		tlsOptions = append(tlsOptions, tlsclient.WithNotFollowRedirects())
	}
	if tlsData.tlsWithRandomExtensionOrder {
		tlsOptions = append(tlsOptions, tlsclient.WithRandomTLSExtensionOrder())
	}
	if tlsData.tlsForceHttp1 {
		tlsOptions = append(tlsOptions, tlsclient.WithForceHttp1())
	}
	if tlsData.tlsInsecureSkipVerify {
		tlsOptions = append(tlsOptions, tlsclient.WithInsecureSkipVerify())
	}
	if tlsData.tlsClientProxy != "" {
		tlsOptions = append(tlsOptions, tlsclient.WithProxyUrl(tlsData.tlsClientProxy))
	}
	return tlsclient.NewHttpClient(tlsclient.NewNoopLogger(), tlsOptions...)
}

type tlsData struct {
	requestUrl                  string
	requestMethod               string
	requestHeaders              map[string][]string
	requestCookies              string
	requestBody                 []byte
	tlsClientProxy              string
	tlsClientProfile            profiles.ClientProfile
	tlsClientTimeout            int
	tlsFollowRedirects          bool
	tlsWithRandomExtensionOrder bool
	tlsForceHttp1               bool
	tlsInsecureSkipVerify       bool
	tlsHeaderOrder              []string
	tlsPseudoHeaderOrder        []string
	tlsShuffleHeaders           bool
}

func extractTlsData(ctx fiber.Ctx) (*tlsData, error) {
	tlsConfig := &tlsData{}
	tlsExtractors := []func(ctx fiber.Ctx) error{
		tlsConfig.extractReqUrl,
		tlsConfig.extractReqMethod,
		tlsConfig.extractReqHeaders,
		tlsConfig.extractReqBody,
		tlsConfig.extractProxy,
		tlsConfig.extractClientProfile,
		tlsConfig.extractClientTimeout,
		tlsConfig.extractFollowRedirects,
		tlsConfig.extractForceHttp1,
		tlsConfig.extractInsecureSkipVerify,
		tlsConfig.extractWithRandomExtensionOrder,
		tlsConfig.extractHeaderOrder,
		tlsConfig.extractPseudoHeaderOrder,
		tlsConfig.extractShuffleHeaders,
	}
	for _, extractor := range tlsExtractors {
		if err := extractor(ctx); err != nil {
			return nil, err
		}
	}
	return tlsConfig, nil
}

func (t *tlsData) extractShuffleHeaders(ctx fiber.Ctx) error {
	shuffle := ctx.Get(tlsShuffleHeadersKey)
	if shuffle == "" {
		shuffle = "false"
	}
	parsed, err := strconv.ParseBool(shuffle)
	if err != nil {
		return fmt.Errorf("invalid shuffle header value: %s", shuffle)
	}
	t.tlsShuffleHeaders = parsed
	return nil
}

func (t *tlsData) extractReqUrl(ctx fiber.Ctx) error {
	reqUrl := ctx.Get(tlsUrlHeaderKey)
	if reqUrl == "" {
		return fmt.Errorf("no %s", tlsUrlHeaderKey)
	}
	_, err := url.Parse(reqUrl)
	if err != nil {
		return err
	}
	t.requestUrl = reqUrl
	return nil
}

func (t *tlsData) extractReqMethod(ctx fiber.Ctx) error {
	reqMethod := ctx.Get(tlsMethodHeaderKey)
	if reqMethod == "" {
		return fmt.Errorf("no %s", tlsMethodHeaderKey)
	}
	if !slices.Contains(supportedReqMethods, reqMethod) {
		return fmt.Errorf("invalid request method: %s", reqMethod)
	}
	t.requestMethod = reqMethod
	return nil
}

func (t *tlsData) extractReqHeaders(ctx fiber.Ctx) error {
	t.requestHeaders = ctx.GetReqHeaders()
	return nil
}

func (t *tlsData) extractReqBody(ctx fiber.Ctx) error {
	t.requestBody = ctx.Body()
	return nil
}

func (t *tlsData) extractProxy(ctx fiber.Ctx) error {
	rawProxy := ctx.Get(tlsProxyHeaderKey)
	if rawProxy != "" {
		formatted, err := utils.FormatProxy(rawProxy)
		if err != nil {
			return err
		}
		t.tlsClientProxy = formatted
	}
	return nil
}

func (t *tlsData) extractClientProfile(ctx fiber.Ctx) error {
	profile := ctx.Get(tlsProfileHeaderKey)
	if profile == "" {
		return fmt.Errorf("no %s", tlsProfileHeaderKey)
	}
	mapped, ok := profiles.MappedTLSClients[profile]
	if !ok {
		return fmt.Errorf("invalid client profile: %s", profile)
	}
	t.tlsClientProfile = mapped
	return nil
}

func (t *tlsData) extractClientTimeout(ctx fiber.Ctx) error {
	raw := ctx.Get(tlsClientTimeoutHeaderKey)
	if raw == "" {
		raw = "30"
	}
	parsed, err := strconv.Atoi(raw)
	if err != nil {
		return fmt.Errorf("invalid client timeout: %s", raw)
	}
	t.tlsClientTimeout = parsed
	return nil
}

func (t *tlsData) extractFollowRedirects(ctx fiber.Ctx) error {
	raw := ctx.Get(tlsFollowRedirectsHeaderKey)
	if raw == "" {
		raw = "true"
	}
	parsed, err := strconv.ParseBool(raw)
	if err != nil {
		return fmt.Errorf("invalid follow redirects: %s", raw)
	}
	t.tlsFollowRedirects = parsed
	return nil
}

func (t *tlsData) extractForceHttp1(ctx fiber.Ctx) error {
	raw := ctx.Get(tlsForceHttp1HeaderKey)
	if raw == "" {
		raw = "false"
	}
	parsed, err := strconv.ParseBool(raw)
	if err != nil {
		return fmt.Errorf("invalid force http1: %s", raw)
	}
	t.tlsForceHttp1 = parsed
	return nil
}

func (t *tlsData) extractInsecureSkipVerify(ctx fiber.Ctx) error {
	raw := ctx.Get(tlsInsecureSkipVerifyHeaderKey)
	if raw == "" {
		raw = "false"
	}
	parsed, err := strconv.ParseBool(raw)
	if err != nil {
		return fmt.Errorf("invalid insecure skip verify: %s", raw)
	}
	t.tlsInsecureSkipVerify = parsed
	return nil
}

func (t *tlsData) extractWithRandomExtensionOrder(ctx fiber.Ctx) error {
	raw := ctx.Get(tlsWithRandomExtensionOrderHeaderKey)
	if raw == "" {
		raw = "true"
	}
	parsed, err := strconv.ParseBool(raw)
	if err != nil {
		return fmt.Errorf("invalid random extension order: %s", raw)
	}
	t.tlsWithRandomExtensionOrder = parsed
	return nil
}

func (t *tlsData) extractHeaderOrder(ctx fiber.Ctx) error {
	raw := ctx.Get(tlsHeaderOrderHeaderKey)
	if raw == "" {
		return fmt.Errorf("no %s", tlsHeaderOrderHeaderKey)
	}
	parts := strings.Split(strings.ReplaceAll(raw, " ", ""), ",")
	if len(parts) == 0 {
		return fmt.Errorf("invalid header order: %s", raw)
	}
	t.tlsHeaderOrder = parts
	return nil
}

func (t *tlsData) extractPseudoHeaderOrder(ctx fiber.Ctx) error {
	raw := ctx.Get(tlsPseudoHeaderOrderHeaderKey)
	if raw == "" {
		return fmt.Errorf("no %s", tlsPseudoHeaderOrderHeaderKey)
	}
	parts := strings.Split(strings.ReplaceAll(raw, " ", ""), ",")
	if len(parts) == 0 {
		return fmt.Errorf("invalid pseudo header order: %s", raw)
	}
	t.tlsPseudoHeaderOrder = parts
	return nil
}

func setRequestHeaders(tlsData *tlsData, req *http.Request) {
	var headerPairs [][2]string
	for key, values := range tlsData.requestHeaders {
		lkey := strings.ToLower(key)
		if strings.HasPrefix(lkey, "x-tls") || lkey == "content-length" || (lkey == "content-type" && slices.Contains(methodsWithoutRequestBody, tlsData.requestMethod)) {
			continue
		}
		for _, val := range values {
			headerPairs = append(headerPairs, [2]string{key, val})
		}
	}
	if tlsData.tlsShuffleHeaders {
		rand.Seed(time.Now().UnixNano())
		rand.Shuffle(len(headerPairs), func(i, j int) {
			headerPairs[i], headerPairs[j] = headerPairs[j], headerPairs[i]
		})
	}
	for _, pair := range headerPairs {
		req.Header.Set(pair[0], pair[1])
	}
	req.Header[http.HeaderOrderKey] = tlsData.tlsHeaderOrder
	req.Header[http.PHeaderOrderKey] = tlsData.tlsPseudoHeaderOrder
}

func getResponseHeaders(resp *http.Response) map[string]string {
	headers := make(map[string]string)
	for k, v := range resp.Header {
		if k != "Content-Length" && k != "Content-Encoding" {
			headers[k] = v[0]
		}
	}
	return headers
}

func setResponseHeaders(ctx fiber.Ctx, reqResponse *requestResponse) {
	for key := range ctx.GetRespHeaders() {
		ctx.Response().Header.Del(key)
	}
	for key, value := range reqResponse.responseHeaders {
		ctx.Set(key, value)
	}
}

func setResponseCookies(ctx fiber.Ctx, reqResponse *requestResponse) {
	for _, c := range reqResponse.responseCookies {
		ctx.Cookie(&fiber.Cookie{
			Name:     c.Name,
			Value:    c.Value,
			Path:     c.Path,
			Domain:   c.Domain,
			MaxAge:   c.MaxAge,
			Expires:  c.Expires,
			Secure:   c.Secure,
			HTTPOnly: c.HttpOnly,
			SameSite: utils.TranslateSameSite(c.SameSite),
		})
	}
}

func handleErrorResponse(ctx fiber.Ctx, message string) error {
	return ctx.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
		"success": false,
		"message": message,
	})
}
