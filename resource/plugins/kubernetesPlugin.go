/*
 * Copyright (C) 2019 Intel Corporation
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
	clog "intel/isecl/lib/common/log"
	"intel/isecl/sgx-attestation-hub/constants"
	"intel/isecl/sgx-attestation-hub/types"
	"io/ioutil"
	"net/http"
	"net/url"
)

var log = clog.GetDefaultLogger()

type Kubernetes struct{}

type PlatformData struct {
	Sgx_enabled   bool   `json:"sgx-enabled"`
	Sgx_supported bool   `json:"sgx-supported"`
	Flc_enabled   bool   `json:"flc-enabled"`
	TcbUpToDate   bool   `json:"tcbUpToDate"`
	Epc_size      string `json:"epc-size"`
	Trusted       bool   `json:"trusted"`
	ValidTo       string `json:"valid_to"`
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
	//Spec       []HostAttributesSpec   `json:"spec"`
	Spec HostList `json:"spec"`
}

type HostAttributesSpec struct {
	Trusted             bool   `json:"trusted"`
	ValidTo             string `json:"valid_to"`
	Sgx_enabled         bool   `json:"sgx-enabled"`
	Sgx_supported       bool   `json:"sgx-supported"`
	Flc_enabled         bool   `json:"flc-enabled"`
	TcbUpToDate         bool   `json:"tcbUpToDate"`
	Epc_size            string `json:"epc-size"`
	Hostname            string `json:"hostName"`
	Signed_trust_report string `json:"signedTrustReport"`
}

func (e *Kubernetes) Pushdata(pData types.PublishData, plugin types.Plugin) error {
	log.Trace("Pushdata entering")
	defer log.Trace("resource/plugin kubernetesPlugin:Pushdata() Leaving")

	////TODO: validate
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
			return errors.Wrap(err, "configuration Unmarshal Failed")
		}
		spec.Sgx_enabled = e.Sgx_enabled
		spec.Sgx_supported = e.Sgx_supported
		spec.Flc_enabled = e.Flc_enabled
		spec.TcbUpToDate = e.TcbUpToDate
		spec.Epc_size = e.Epc_size
		spec.Hostname = p1.Hostname
		spec.Trusted = e.Trusted
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
	//var serverPass string ///TODO: Currently not being used as truststore is not being parsed
	for _, ss := range arr1 {
		log.Trace("hostAttributes: ", ss)
		///Each CRD push data
		tenantId := tenantIdStr ///get from crdData.MetaData
		///Build End point urls and publish to K8s
		var value string
		for _, property := range plugin.Properties {
			if property.Key == "api.endpoint" {
				value = property.Value
			} else if property.Key == "kubernetes.client.keystore.password" { ///TODO: This all will go in constants.go once we merge all code
				clientPass = property.Value
			} else if property.Key == "kubernetes.server.keystore.password" {
				//serverPass = property.Value ///TODO: Not able to parse server trustore.
			} else if property.Key == "kubernetes.client.keystore" {
				clientKeystore = property.Value
			} else if property.Key == "kubernetes.server.keystore" {
				serverKeystore = property.Value
			}
		}

		//https: //<k8s-master-IP>:6443/apis/crd.isecl.intel.com/v1beta1/namespaces/default/hostattributes/<tenant-id>-isecl-attributes-object
		k8s_url = value + constants.PATH + constants.SLASH + constants.URL_HOSTATTRIBUTES + constants.SLASH + tenantId + "-isecl-attributes-object"
	}
	CaCert, err := ioutil.ReadFile(serverKeystore)
	if err != nil {
		log.Error("error came in reading CaCert: ", err)
		return errors.Wrap(err, "Can't read CaCert")
	}

	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(CaCert)

	encryptedCert, err := ioutil.ReadFile(clientKeystore)
	if err != nil {
		log.Error("error came in reading client cetificate: ", err)
		return errors.Wrap(err, "Can't read clientCerificate")
	}
	key, cert, err := pkcs12.Decode(encryptedCert, clientPass)
	if err != nil {
		log.Error("error came in decoding client cetificate: ", err)
		return errors.Wrap(err, "Can't decode clientCerificate")
	}
	value, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		log.Error("error came in x509.MarshalPKCS8PrivateKey: ", err)
		return errors.Wrap(err, "Can't marshal key")
	}
	pemCert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	pemKey := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: value})
	clientCert, err := tls.X509KeyPair(pemCert, pemKey)
	if err != nil {
		log.Error("error came in tls.X509KeyPair: ", err)
		return errors.Wrap(err, "can't create keyPair")
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
		return errors.Wrap(err, "URL parsing failed")
	}
	req, err := http.NewRequest("GET", url.String(), nil)
	if err != nil {
		return errors.Wrap(err, "http NewRequest failed")
	}
	r, err := client.Do(req)
	if err != nil {
		return errors.Wrap(err, "client.Do failed")
	}

	//r, err := client.Get(url)
	//req, err := http.NewRequest("GET", url, nil)
	//r, err := client.Do(req)
	if err != nil {
		return errors.Wrap(err, "GET Call failed")
	}
	// Read the response body
	defer r.Body.Close()

	if r.StatusCode == http.StatusOK {
		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			return errors.Wrap(err, "error came in ioutil.ReadAll")
		}
		var hCRD HostAttributesCRD
		err = json.Unmarshal(body, &hCRD)
		if err != nil {
			return errors.Wrap(err, "error came in unmarshalling")
		}
		///Get MetaData from this
		crdData.Metadata.ResourceVersion = hCRD.Metadata.ResourceVersion
		log.Trace("crdData: ", crdData)

		reqBytes, err := json.Marshal(crdData)
		if err != nil {
			return errors.Wrap(err, "error came in Marshalling CRDData")
		}

		req, err := http.NewRequest(http.MethodPut, url.String(), bytes.NewBuffer(reqBytes))
		if err != nil {
			return errors.Wrap(err, "PUT call failed here")
		}
		req.Header.Set("Content-Type", "application/json")

		resp, err := client.Do(req)
		if err != nil {
			return errors.Wrap(err, "PushSGXData: Error while caching Host Status Information: "+err.Error())
		}
		log.Info("PUT response status: ", resp.StatusCode)
		_, err = ioutil.ReadAll(resp.Body)
		if err != nil || resp.StatusCode != http.StatusOK {
			return errors.Wrap(err, "PUT call ioutil.ReadAll failed")
		}
		resp.Body.Close()
	} else if r.StatusCode == http.StatusNotFound {
		reqBytes, err := json.Marshal(crdData)
		if err != nil {
			return errors.Wrap(err, "error came in Marshalling crdData")
		}
		req, err := http.NewRequest(http.MethodPost, url.String(), bytes.NewBuffer(reqBytes))
		if err != nil {
			return errors.Wrap(err, "POST call failed here")
		}
		req.Header.Set("Content-Type", "application/json")

		resp, err := client.Do(req)
		if err != nil {
			return errors.Wrap(err, "PushSGXData: Error while caching Host Status Information: "+err.Error())
		}
		log.Info("POST response status: ", resp.StatusCode)
		_, err = ioutil.ReadAll(resp.Body)
		if err != nil || resp.StatusCode != http.StatusCreated {
			return errors.Wrap(err, "POST call ioutil.ReadAll failed")
		}
		resp.Body.Close()
	}
	r.Body.Close()
	return nil
}

func validateAndSend(plugin types.Plugin) {
	log.Info("validateAndSend entering")
	///We will validate later
	///	generateCrd(data)

}
