/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package plugins

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"github.com/pkg/errors"
	"golang.org/x/crypto/pkcs12"
	clog "intel/isecl/lib/common/v3/log"
	commLogMsg "intel/isecl/lib/common/v3/log/message"
	"intel/isecl/shub/constants"
	"intel/isecl/shub/types"
	"io/ioutil"
	"net/http"
	"net/url"
)

var log = clog.GetDefaultLogger()
var slog = clog.GetSecurityLogger()

type Kubernetes struct{}

type PlatformData struct {
	Sgx_enabled   bool   `json:"sgx-enabled"`
	Sgx_supported bool   `json:"sgx-supported"`
	Flc_enabled   bool   `json:"flc-enabled"`
	TcbUpToDate   bool   `json:"tcbUpToDate"`
	Epc_size      string `json:"epc-size"`
	ValidTo       string `json:"validTo"`
}

type HostAttributesMetadata struct {
	Name            string `json:"name"`
	ResourceVersion string `json:"resourceVersion,omitempty"`
}
type HostList struct {
	HostAttributesArray []HostAttributesSpec `json:"hostList"`
}

type HostAttributesCRD struct {
	Metadata   HostAttributesMetadata `json:"metadata"`
	ApiVersion string                 `json:"apiVersion"`
	Kind       string                 `json:"kind"`
	Spec       HostList               `json:"spec"`
}

type HostAttributesSpec struct {
	ValidTo             string `json:"validTo"`
	Sgx_enabled         bool   `json:"sgx-enabled"`
	Sgx_supported       bool   `json:"sgx-supported"`
	Flc_enabled         bool   `json:"flc-enabled"`
	TcbUpToDate         bool   `json:"tcbUpToDate"`
	Epc_size            string `json:"epc-size"`
	Hostname            string `json:"hostName"`
	Signed_trust_report string `json:"signedTrustReport"`
}

func (e *Kubernetes) Pushdata(pData types.PublishData, plugin types.Plugin) error {
	log.Trace("resource/plugins/kubernetesPlugin: Pushdata() entering")
	defer log.Trace("resource/plugins/kubernetesPlugin: Pushdata() Leaving")

	var hostSpecArr []HostAttributesSpec
	for _, p1 := range pData.Host_details {

		///Unmarshal hostDetails.trust_report and create a json object
		///get signedReport
		///Create a struct representing values ot be snet to K8s
		///Initialize these values to it
		var spec HostAttributesSpec
		spec.Signed_trust_report = p1.Signed_trust_report
		var e PlatformData
		err := json.Unmarshal(([]byte(p1.Trust_report)), &e)
		if err != nil {
			return errors.Wrap(err, "Pushdata: configuration Unmarshal Failed")
		}
		spec.Sgx_enabled = e.Sgx_enabled
		spec.Sgx_supported = e.Sgx_supported
		spec.Flc_enabled = e.Flc_enabled
		spec.TcbUpToDate = e.TcbUpToDate
		spec.Epc_size = e.Epc_size
		spec.Hostname = p1.Hostname
		spec.ValidTo = e.ValidTo
		hostSpecArr = append(hostSpecArr, spec)
	}
	tenantIdStr := string(pData.TenantId)
	var mdata HostAttributesMetadata
	mdata.Name = tenantIdStr + "-isecl-attributes-object"
	var crdData HostAttributesCRD
	crdData.Metadata = mdata
	crdData.ApiVersion = constants.API_VERSION
	crdData.Kind = constants.HOSTATTRIBUTES_CRD
	crdData.Spec.HostAttributesArray = hostSpecArr
	var arr1 []HostAttributesCRD
	arr1 = append(arr1, crdData)
	var k8s_url, clientPass, serverKeystore, clientKeystore string

	for _, ss := range arr1 {
		log.Debug("hostAttributes: ", ss)
		///Each CRD push data
		tenantId := tenantIdStr ///get from crdData.MetaData
		///Build End point urls and publish to K8s
		var value string
		for _, property := range plugin.Properties {
			if property.Key == "api.endpoint" {
				value = property.Value
			} else if property.Key == constants.KubernetesClientKeystorePassword {
				clientPass = property.Value
			} else if property.Key == constants.KubernetesClientKeystore {
				clientKeystore = property.Value
			} else if property.Key == constants.KubernetesServerKeystore {
				serverKeystore = property.Value
			}
		}
		//https: //<k8s-master-IP>:6443/apis/crd.isecl.intel.com/v1beta1/namespaces/default/hostattributes/<tenant-id>-isecl-attributes-object
		k8s_url = value + constants.PATH + constants.SLASH + constants.URL_HOSTATTRIBUTES + constants.SLASH + tenantId + "-isecl-attributes-object"
	}
	CaCert, err := ioutil.ReadFile(serverKeystore)
	if err != nil {
		return errors.Wrap(err, "Pushdata: Can't read CaCert")
	}

	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(CaCert)

	encryptedCert, err := ioutil.ReadFile(clientKeystore)
	if err != nil {
		return errors.Wrap(err, "Pushdata: Can't read client certificate")
	}
	key, cert, err := pkcs12.Decode(encryptedCert, clientPass)
	if err != nil {
		slog.WithError(err).Error(commLogMsg.InvalidInputBadEncoding)
		return errors.Wrap(err, "Pushdata: Can't decode client certificate")
	}
	value, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		log.WithError(err).Info("Pushdata: error came in x509.MarshalPKCS8PrivateKey")
		return errors.Wrap(err, "Pushdata: Can't marshal private key")
	}
	pemCert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	pemKey := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: value})
	clientCert, err := tls.X509KeyPair(pemCert, pemKey)
	if err != nil {
		log.WithError(err).Info("Pushdata: error came in tls.X509KeyPair")
		return errors.Wrap(err, "Pushdata: can't create keyPair")
	}

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:      caCertPool,
				Certificates: []tls.Certificate{clientCert},
			},
		},
	}
	url, err := url.Parse(k8s_url)
	if err != nil {
		return errors.Wrap(err, "Pushdata: URL parsing failed")
	}
	req, err := http.NewRequest("GET", url.String(), nil)
	if err != nil {
		return errors.Wrap(err, "Pushdata: http NewRequest failed")
	}
	r, err := client.Do(req)
	if err != nil {
		return errors.Wrap(err, "Pushdata: GET client call failed")
	}

	// Read the response body
	defer r.Body.Close()

	if r.StatusCode == http.StatusOK {
		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			return errors.Wrap(err, "Pushdata: error while reading response body")
		}
		var hCRD HostAttributesCRD
		err = json.Unmarshal(body, &hCRD)
		if err != nil {
			return errors.Wrap(err, "Pushdata: error while unmarshalling the data")
		}
		///Get MetaData from this
		crdData.Metadata.ResourceVersion = hCRD.Metadata.ResourceVersion

		reqBytes, err := json.Marshal(crdData)
		if err != nil {
			return errors.Wrap(err, "Pushdata: error came in Marshalling CRDData")
		}

		req, err := http.NewRequest(http.MethodPut, url.String(), bytes.NewBuffer(reqBytes))
		if err != nil {
			return errors.Wrap(err, "Pushdata: Error creating new request")
		}
		req.Header.Set("Content-Type", "application/json")

		resp, err := client.Do(req)
		if err != nil {
			return errors.Wrap(err, "Pushdata: PUT client call failed: "+err.Error())
		}
		log.Debug("PUT response status: ", resp.StatusCode)
		_, err = ioutil.ReadAll(resp.Body)
		if err != nil || resp.StatusCode != http.StatusOK {
			return errors.Wrap(err, "Pushdata: PUT error while reading response body")
		}
		resp.Body.Close()
	} else if r.StatusCode == http.StatusNotFound {
		reqBytes, err := json.Marshal(crdData)
		if err != nil {
			return errors.Wrap(err, "Pushdata: error came in Marshalling crdData")
		}
		req, err := http.NewRequest(http.MethodPost, url.String(), bytes.NewBuffer(reqBytes))
		if err != nil {
			return errors.Wrap(err, "Pushdata: POST error while creating new request")
		}
		req.Header.Set("Content-Type", "application/json")

		resp, err := client.Do(req)
		if err != nil {
			return errors.Wrap(err, "PushSGXData: Error while caching Host Status Information: "+err.Error())
		}
		log.Debug("Pushdata: POST response status: ", resp.StatusCode)
		_, err = ioutil.ReadAll(resp.Body)
		if err != nil || resp.StatusCode != http.StatusCreated {
			return errors.Wrap(err, "Pushdata: POST error while reading response body")
		}
		resp.Body.Close()
	}
	r.Body.Close()
	return nil
}
