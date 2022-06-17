package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httputil"
	"time"
)

const YandexConnectLiveDnsBaseUrl = "https://pddimp.yandex.ru/api2/admin/dns"

type YandexConnectClient struct {
	pddToken            string
	dumpRequestResponse bool
}

type YandexConnectListResponse struct {
	Domain  string                   `json:"domain"`
	Records []YandexConnectDnsRecord `json:"records"`
	Success string                   `json:"success"`
	Error   string                   `json:"error"`
}

type YandexConnectAddResponse struct {
	Domain  string                 `json:"domain"`
	Record  YandexConnectDnsRecord `json:"record"`
	Success string                 `json:"success"`
	Error   string                 `json:"error"`
}

type YandexConnectUpdateResponse struct {
	Domain  string                 `json:"domain"`
	Record  YandexConnectDnsRecord `json:"record"`
	Success string                 `json:"success"`
	Error   string                 `json:"error"`
}

type YandexConnectDeleteResponse struct {
	Domain   string `json:"domain"`
	RecordId uint64 `json:"record_id"`
	Success  string `json:"success"`
	Error    string `json:"error"`
}

type YandexConnectDnsRecord struct {
	RecordId  uint64 `json:"record_id"`
	Type      string `json:"type"`
	Domain    string `json:"domain"`
	Fqdn      string `json:"fqdn"`
	Ttl       uint64 `json:"ttl"`
	Subdomain string `json:"subdomain"`
	Content   string `json:"content"`
	Priority  uint32 `json:"priority"`
}

func NewYandexConnectClient(pddToken string) *YandexConnectClient {
	return &YandexConnectClient{
		pddToken:            pddToken,
		dumpRequestResponse: false,
	}
}

func (yandexConnectClient *YandexConnectClient) HasTxtRecord(domain *string, name *string) (bool, error) {
	record, error := yandexConnectClient.getTextRecord(domain, name)

	if error != nil {
		return false, nil
	}

	return record != nil, nil
}

func (yandexConnectClient *YandexConnectClient) CreateTxtRecord(domain *string, name *string, value *string, ttl int) error {
	// curl -X POST \
	//   -H "PddToken: $PddToken" \
	//   https://pddimp.yandex.ru/api2/admin/dns/add?domain=<DOMAIN>&subdomain=<NAME>&type=<TYPE>&content=<VALUE>&ttl=<TTL>
	url := fmt.Sprintf("%s/add?domain=%s&subdomain=%s&type=TXT&content=%s&ttl=%d", YandexConnectLiveDnsBaseUrl, *domain, *name, *value, ttl)
	request, error := http.NewRequest("POST", url, nil)
	if error != nil {
		return error
	}

	data, error := yandexConnectClient.doRequest(request)
	if error != nil {
		return error
	}

	var response YandexConnectAddResponse
	json.Unmarshal(data, &response)

	if response.Success == "error" {
		// TODO: Translate error code into error message.
		return fmt.Errorf("add DNS-record request for domain %s failed with error: '%s'", *domain, response.Error)
	}

	return nil
}

func (yandexConnectClient *YandexConnectClient) UpdateTxtRecord(domain *string, name *string, value *string, ttl int) error {
	record, error := yandexConnectClient.getTextRecord(domain, name)
	if error != nil {
		return error
	}

	// curl -X POST \
	//   -H "PddToken: $PddToken" \
	//   https://pddimp.yandex.ru/api2/admin/dns/edit?record_id=<RECORD_ID>&domain=<DOMAIN>&content=<VALUE>&ttl=<TTL>
	url := fmt.Sprintf("%s/edit?record_id=%d&domain=%s&subdomain=%s&type=TXT&content=%s&ttl=%d", YandexConnectLiveDnsBaseUrl, record.RecordId, *domain, *name, *value, ttl)
	request, error := http.NewRequest("POST", url, nil)
	if error != nil {
		return error
	}

	data, error := yandexConnectClient.doRequest(request)
	if error != nil {
		return error
	}

	var response YandexConnectUpdateResponse
	json.Unmarshal(data, &response)

	if response.Success == "error" {
		// TODO: Translate error code into error message.
		return fmt.Errorf("update DNS-record request for domain %s failed with error: '%s'", *domain, response.Error)
	}

	return nil
}

func (yandexConnectClient *YandexConnectClient) DeleteTxtRecord(domain *string, name *string) error {
	record, error := yandexConnectClient.getTextRecord(domain, name)
	if error != nil {
		return error
	}

	// curl -X POST \
	//   -H "PddToken: $PddToken" \
	//   https://pddimp.yandex.ru/api2/admin/dns/del?record_id=<RECORD_ID>&domain=<DOMAIN>
	url := fmt.Sprintf("%s/del?record_id=%d&domain=%s", YandexConnectLiveDnsBaseUrl, record.RecordId, *domain)
	request, error := http.NewRequest("POST", url, nil)
	if error != nil {
		return error
	}

	data, error := yandexConnectClient.doRequest(request)
	if error != nil {
		return error
	}

	var response YandexConnectDeleteResponse
	json.Unmarshal(data, &response)

	if response.Success == "error" {
		// TODO: Translate error code into error message.
		return fmt.Errorf("delete DNS-record request for domain %s failed with error: '%s'", *domain, response.Error)
	}

	return nil
}

func (yandexConnectClient *YandexConnectClient) doRequest(request *http.Request) ([]byte, error) {
	if yandexConnectClient.dumpRequestResponse {
		dump, _ := httputil.DumpRequest(request, true)
		fmt.Printf("Request: %q\n", dump)
	}

	request.Header.Set("PddToken", yandexConnectClient.pddToken)
	httpClient := http.Client{
		Timeout: 30 * time.Second,
	}

	response, error := httpClient.Do(request)
	if error != nil {
		return nil, error
	}

	if yandexConnectClient.dumpRequestResponse {
		dump, _ := httputil.DumpResponse(response, true)
		fmt.Printf("Response: %q\n", dump)
	}

	data, error := ioutil.ReadAll(response.Body)
	if error != nil {
		return nil, error
	}

	return data, nil
}

func (yandexConnectClient *YandexConnectClient) getTextRecord(domain *string, name *string) (*YandexConnectDnsRecord, error) {
	// curl -X GET \
	//   -H "PddToken: $PddToken" \
	//   https://pddimp.yandex.ru/api2/admin/dns/list?domain=<DOMAIN>
	url := fmt.Sprintf("%s/list?domain=%s", YandexConnectLiveDnsBaseUrl, *domain)
	request, error := http.NewRequest("GET", url, nil)
	if error != nil {
		return nil, error
	}

	data, error := yandexConnectClient.doRequest(request)
	if error != nil {
		return nil, error
	}

	var response YandexConnectListResponse
	json.Unmarshal(data, &response)

	// API response always 200 OK even for fails.
	if response.Success == "error" {
		// TODO: Translate error code into error message.
		return nil, fmt.Errorf("list DNS-records request for domain %s failed with error: '%s'", *domain, response.Error)
	}

	for _, record := range response.Records {
		if record.Type == "TXT" && record.Subdomain == *name {
			return &record, nil
		}
	}

	return nil, nil
}
