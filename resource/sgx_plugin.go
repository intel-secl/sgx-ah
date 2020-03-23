/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package resource

import (
	"bytes"
	"encoding/json"
	//"fmt"
	"github.com/pkg/errors"
	"intel/isecl/sgx-attestation-hub/constants"
	"intel/isecl/sgx-attestation-hub/repository"
	"intel/isecl/sgx-attestation-hub/types"
	"net/http"

	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	//"golang.org/x/crypto/pkcs12"

	//"encoding/pem"

	"io/ioutil"
	//"strings"
)

type Property struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

type Plugin struct {
	Name       string     `json:"name,omitempty"`
	Properties []Property `json:"properties"`
}

type tenantConfig struct {
	TenantId   string   `json:"id"`
	TenantName string   `json:"name"`
	Plugins    []Plugin `json:"plugins"`
	Deleted    bool     `json:"deleted"`
}

type hostDetails struct {
	uuid                string
	hardwareUuid        string
	trust_report        string
	hostname            string
	signed_trust_report string
}
type PublishData struct {
	host_details []hostDetails
	tenantId     string
}

type PlatformData struct {
	Sgx_enabled   bool   `json:"sgx-enabled"`
	Sgx_supported bool   `json:"sgx-supported"`
	Flc_enabled   bool   `json:"flc-enabled"`
	TcbUpToDate   bool   `json:"tcbUpToDate"`
	Epc_size      string `json:"epc-size"`
	Trusted       bool   `json:"trusted"`
	ValidTo       string `json:"valid_to"`
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

type HostAttributesMetadata struct {
	Name string `json:"name"`
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

type JwtHeader struct {
	KeyId     string `json:"kid,omitempty"`
	Type      string `json:"typ,omitempty"`
	Algorithm string `json:"alg,omitempty"`
}

func (e *tenantConfig) GetConfigStruct(configuartion string) error {

	log.Info("resource/sgx_plugin:GetConfigStruct() Entering: ", configuartion)
	defer log.Trace("resource/sgx_plugin:GetConfigStruct() Leaving")

	err := json.Unmarshal(([]byte(configuartion)), e)
	if err != nil {
		log.Info("trace shef 1: ", err)
		return errors.Wrap(err, "configuration Unmarshal Failed")
	}
	log.Info("trace shef 2: ", *e)
	return nil
}

func (e *Plugin) GetCredentials(configuartion string) error {
	log.Info("resource/sgx_plugin:GetCredentials() Entering: ", configuartion)
	defer log.Trace("resource/sgx_plugin:GetConfigStruct() Leaving")
	err := json.Unmarshal(([]byte(configuartion)), e)
	if err != nil {
		log.Info("trace shef 1: ", err)
		return errors.Wrap(err, "configuration Unmarshal Failed")
	}
	log.Info("trace shef 2: ", *e)
	return err
}

func GetAHPublicKey() []byte {
	rsaPublicKeyLocation := constants.PublickeyLocation
	pubKey, err := ioutil.ReadFile(rsaPublicKeyLocation)
	if err != nil {
		log.Info("Error in reading the hub pem file:", err)
	}
	return pubKey
}

func createSignedTrustReport(createSignedTrustReport string) (string, error) {
	log.Info("In createSignedTrustReport")
	///Get the privateKeyFromPath
	var privateKey *rsa.PrivateKey
	rsaPrivateKeyLocation := constants.PrivatekeyLocation
	rsaPublicKeyLocation := constants.PublickeyLocation

	priv, err := ioutil.ReadFile(rsaPrivateKeyLocation)
	if err != nil {
		log.Error("no rsa private key found: ", err)
		return "", errors.New("no rsa key file path provided")
	}

	parsedKey, err := x509.ParsePKCS8PrivateKey(priv)
	if err != nil {
		log.Error("Cannot parse RSA private key from file: ", err)
		return "", errors.New("Cannot parse RSA private key from file")
	}
	privateKey, ok := parsedKey.(*rsa.PrivateKey)
	if !ok {
		log.Error("Unable to parse RSA private key")
		return "", errors.New("Unable to parse RSA private key")
	}
	log.Info("trace 1")

	publicKey, err := ioutil.ReadFile(rsaPublicKeyLocation)
	if err != nil {
		log.Error("no rsa public key found: ", err)
		return "", errors.New("no rsa key file path provided")
	}
	pubPem, _ := pem.Decode(publicKey)
	if pubPem == nil {
		log.Error("rsa public key not decoded")
		return "", errors.New("rsa public key not decoded")
	}

	h := sha1.New()
	h.Write(pubPem.Bytes)
	bs := h.Sum(nil)
	keyIdStr := base64.StdEncoding.EncodeToString(bs)

	header := make(map[string]string)
	header["alg"] = "RS384"
	header["typ"] = "JWT"
	header["kid"] = keyIdStr
	b, _ := json.Marshal(header)

	hashEntity := sha512.New384()
	hashEntity.Write([]byte(createSignedTrustReport))
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA384, hashEntity.Sum(nil))
	signedTrustReportBytes := base64.StdEncoding.EncodeToString([]byte(createSignedTrustReport))
	str1 := base64.StdEncoding.EncodeToString(b)
	signatureString := str1 + "." + signedTrustReportBytes + "." + base64.StdEncoding.EncodeToString(signature)

	/*
		parts := strings.Split(signatureString, ".")
		if len(parts) != 3 {
			return "", errors.New("Invalid token received, token must have 3 parts")
		}
		log.Info("parts[0]: ", parts[0])
		log.Info("str1: ", str1)

		jwtHeaderRcvd, _ := base64.StdEncoding.DecodeString(parts[0])
		var jwtHeader JwtHeader
		err = json.Unmarshal(jwtHeaderRcvd, &jwtHeader)
		if err != nil {
			//Log.Errorf("%+v", err)
			log.Info("error came: ", err)
			return "", errors.New("Failed to unmarshal jwt header")
		}
		pubKey := GetAHPublicKey()
		block, _ := pem.Decode(pubKey)
		if block == nil || block.Type != "PUBLIC KEY" {
			log.Info("failed to decode PEM block containing public key")
		}
		keyIdBytes := sha1.Sum(block.Bytes)
		keyIdStr1 := base64.StdEncoding.EncodeToString(keyIdBytes[:])
		log.Info("jwtHeader.KeyId: ", jwtHeader.KeyId)
		log.Info("keyIdStr: ", keyIdStr1)

		if jwtHeader.KeyId != keyIdStr1 {
			log.Info("Invalid Kid")
		}

		return str1, nil
	*/

	return signatureString, nil
}

func SynchAttestationInfo(db repository.SAHDatabase) error {
	log.Info("Calling out plugins to push host data")
	log.Trace("resource/synchAttestationInfo: synchAttestationInfo() Entering")
	defer log.Trace("resource/synchAttestationInfo: synchAttestationInfo() Leaving")

	ext_tennats, err := db.TenantRepository().RetrieveAllActiveTenants()
	if ext_tennats == nil {
		log.Info("No tenants configured")
		return err
	}
	log.Info("Tenants retrieved: ", len(ext_tennats))
	for _, tenant := range ext_tennats {
		///Read Tenant Configuration
		///Get configuration string and convert that string to corresponding key value pair
		/// get ahMapping data: getHostHardwareUuid()
		///get hosts data for the getHostHardwareUuid()
		///	populateHostDetails()
		configuartion := tenant.Config
		log.Info("configuartion: ", configuartion)
		configStruct := new(tenantConfig)
		///configuartion is a string containing keys and values information
		err = configStruct.GetConfigStruct(configuartion)
		if err != nil {
			log.Info("trace 1")
			return errors.Wrap(err, "synchAttestationInfo: Failed to get configurations")
		}
		/// get ahMapping data: getHostHardwareUuid(). Get all the mappings with given tenantID and deleted = false.
		log.Info("trace 2: ", tenant.Id)
		configStruct.TenantId = tenant.Id
		tenant_mapping, err := db.HostTenantMappingRepository().RetrieveAll(types.HostTenantMapping{TenantUUID: tenant.Id, Deleted: false})
		if err != nil {
			return errors.Wrap(err, "synchAttestationInfo: Failed to get tenant mapping")
		}
		log.Info("tenant_mapping retrieved: ", len(tenant_mapping))

		var hostDataSlice []hostDetails
		for _, mapping := range tenant_mapping {
			hardwareuuid := mapping.HostHardwareUUID
			log.Info("hardwareuuid: ", hardwareuuid)
			host, err := db.HostRepository().Retrieve(types.Host{HardwareUUID: hardwareuuid, Deleted: false})
			if host == nil {
				log.Info("No host with this uuid")
				return err
			}
			log.Info("trace 3 host infomartion: ", host)
			hostDetailsPtr, err := populateHostDetails(host)
			log.Info("trace 4")
			if err != nil {
				return errors.Wrap(err, "synchAttestationInfo: Failed to get configurations")
			}
			///Now add the host in a list of hosts
			log.Info("hostDetails: ", hostDetailsPtr)
			hostDataSlice = append(hostDataSlice, *hostDetailsPtr)
		}
		log.Info("hostDataSlice size: ", len(hostDataSlice))
		processDataToPlugins(tenant, hostDataSlice, configStruct.Plugins, db)
	}

	return nil
}

func processDataToPlugins(t1 types.Tenant, h1 []hostDetails, p1 []Plugin, db repository.SAHDatabase) error {
	log.Info("t1: ", t1)
	log.Info("h1: ", h1)
	log.Info("p1: ", p1)
	for _, plugin := range p1 {
		var pData PublishData
		pData.tenantId = t1.Id
		pData.host_details = h1
		log.Info("pData: ", pData)
		var value string
		for _, property := range plugin.Properties {
			log.Info("property: ", property)
			if property.Key == "plugin.provider" {
				value = property.Value
				break
			}
		}
		if value == "" {
			////report error
			log.Info("value of plugin provider is null")
			return errors.New("value of plugin provider is null")
			//return nil
		}
		///Get Plugin class name
		err := addCredentialToPlugin(t1, plugin, db)
		if err != nil {
			log.Info("got error: ", err)
			return err
		}
		if value == "Kubernetes" {
			err := Pushdata(pData, plugin)
			if err != nil {
				log.Info("got error: ", err)
				return err
			}
		} else if value == "OpenStack" {
		} else {
			///error
			log.Info("plugin provider doesn't match")
			return errors.New("plugin provider doesn't match")
		}
	}
	return nil
}

func Pushdata(pData PublishData, plugin Plugin) error {
	log.Info("Pushdata entering: ", pData)
	///Convert PublishData to json string
	/*js, err := json.Marshal(pData)
	log.Info("js: ", js)
	if err != nil {
		log.Info("Marshalling unsuccessful")
		return err
	}*/
	////TODO: validate

	var hostSpecArr []HostAttributesSpec
	for _, p1 := range pData.host_details {
		///Unmarshal hostDetails.trust_report and create a json object
		///get signedReport
		///Create a struct representing values ot be snet to K8s
		///Initialize these values to it
		var v1 HostAttributesSpec
		v1.Signed_trust_report = p1.signed_trust_report
		var e PlatformData
		log.Info("p1.trust_report: ", p1.trust_report)
		err := json.Unmarshal(([]byte(p1.trust_report)), &e)
		if err != nil {
			log.Info("trace shef 1: ", err)
			return errors.Wrap(err, "configuration Unmarshal Failed")
		}
		v1.Sgx_enabled = e.Sgx_enabled
		v1.Sgx_supported = e.Sgx_supported
		v1.Flc_enabled = e.Flc_enabled
		v1.TcbUpToDate = e.TcbUpToDate
		v1.Epc_size = e.Epc_size
		v1.Hostname = p1.hostname
		v1.Trusted = e.Trusted
		v1.ValidTo = e.ValidTo
		hostSpecArr = append(hostSpecArr, v1)
	}
	log.Info("host attributes in CRD: ", hostSpecArr)
	str := string(pData.tenantId)
	var m1 HostAttributesMetadata
	m1.Name = str + "-isecl-attributes-object"
	var v2 HostAttributesCRD
	v2.Metadata = m1
	v2.ApiVersion = constants.API_VERSION
	v2.Kind = constants.HOSTATTRIBUTES_CRD
	v2.Spec.HostAttributesArray = hostSpecArr
	log.Info("final CRD Data: ", v2)
	b, _ := json.Marshal(v2)
	s := string(b)
	log.Info("s: ", s)
	var arr1 []HostAttributesCRD
	arr1 = append(arr1, v2)
	var url string
	for _, ss := range arr1 {
		log.Info("ss: ", ss)
		///Each CRD push data
		tenantId := str ///get from v2.MetaData
		//crdKind := ss.Kind
		urlKind := constants.URL_HOSTATTRIBUTES
		///Build End point urls and publish to K8s
		var value string
		for _, property := range plugin.Properties {
			log.Info("property: ", property)
			if property.Key == "api.endpoint" {
				value = property.Value
				break
			}
		}

		url = value + constants.PATH + urlKind + constants.SLASH + tenantId
		//https: //<k8s-master-IP>:6443/apis/crd.isecl.intel.com/v1beta1/namespaces/default/hostattributes/<tenant-id>-isecl-attributes-object

		///Hard Coding the url as of now
		url = "https://10.80.245.179:6443/apis/crd.isecl.intel.com/v1beta1/namespaces/default/hostattributes/6f52b2e6-0352-42df-bb73-2d865e71520b-isecl-attributes-object"
	}
	CaCert, err := ioutil.ReadFile("/etc/certs/root-ca.pem")
	if err != nil {
		log.Info("error came in CaCert: ", err)
		return err
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(CaCert)

	cert, err := tls.LoadX509KeyPair("/etc/certs/cert.pem", "/etc/certs/key.pem")
	if err != nil {
		log.Info("error came: ", err)
		return err
	}

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:      caCertPool,
				Certificates: []tls.Certificate{cert},
			},
		},
	}
	// Request /hello via the created HTTPS client over port 8443 via GET
	log.Info("url: ", url)
	r, err := client.Get(url)
	if err != nil {
		log.Info("error came in client.Get: ", err)
		return err
	}
	// Read the response body
	defer r.Body.Close()
	/*body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Info("error came in ioutil.ReadAll: ", err)
		return err
	}*/

	if r.StatusCode == 404 {
		///Post request will be done then
		//str2 := `{"apiVersion":"crd.isecl.intel.com/v1beta1","kind":"HostAttributesCrd","metadata":{"name":"6f52b2e6-0352-42df-bb73-2d865e71520b-isecl-attributes-object"},"spec":{"hostList":[{"hostName":"10.165.58.28","sgx-enabled":"true","signedTrustReport":"Miiy3fienrv96pLMElkW/vgf3pwyqK22EbO22FPcZI02wswvdU1wTDo7HI1Ipwc5cxDowKU92qOpcG34mEUDfQqNpvkssjyoOCkAfgvz5QO/1OLkcb600dUEC6x8PT9vw6OMkvYAzhLS/2iZgaW+x2vEryqyfbNnFEDb54jLvUcfD24AzMmWSomgkVhb1+w6oJ0iRjBR6IweJnr5WRTnlTlrnvqIGUiKpuktxgf++G0n3oXvsVAFiZaqzFrb96VmBJ0IrtzK1P0g6YX0BU6aeYc3Ajyg9b127yQSvWIJnZupzfIGeyYPj2NbykSQg6HUOVLYJ65seBGraFWAjI17dLELD2JPfjv+3+uotPPBlAnbwUG6mQTJoX3dtzhSa63y3qvIiWZFDvLzgHG5nobvGXMGb3ZByAJ8qiL/z3QrcN4ENikur/BVme+xrUG9e6I2ceRbhbnZXsWg9kqBB6gDpOO0Kl66Kqy7QENK8ij84+Dn+bGzZ2b3i/crIJIvAfld}{truetrue10.165.58.28Miiy3fienrv96pLMElkW/vgf3pwyqK22EbO22FPcZI02wswvdU1wTDo7HI1Ipwc5cxDowKU92qOpcG34mEUDfQqNpvkssjyoOCkAfgvz5QO/1OLkcb600dUEC6x8PT9vw6OMkvYAzhLS/2iZgaW+x2vEryqyfbNnFEDb54jLvUcfD24AzMmWSomgkVhb1+w6oJ0iRjBR6IweJnr5WRTnlTlrnvqIGUiKpuktxgf++G0n3oXvsVAFiZaqzFrb96VmBJ0IrtzK1P0g6YX0BU6aeYc3Ajyg9b127yQSvWIJnZupzfIGeyYPj2NbykSQg6HUOVLYJ65seBGraFWAjI17dLELD2JPfjv+3+uotPPBlAnbwUG6mQTJoX3dtzhSa63y3qvIiWZFDvLzgHG5nobvGXMGb3ZByAJ8qiL/z3QrcN4ENikur/BVme+xrUG9e6I2ceRbhbnZXsWg9kqBB6gDpOO0Kl66Kqy7QENK8ij84+Dn+bGzZ2b3i/crIJIvAfld"}]}}`

		//reqBytes := []byte(str2)
		reqBytes, err := json.Marshal(v2)
		log.Info("reqBytes: ", string(reqBytes))
		if err != nil {
			log.Info("error came in Marshalling: ", err)
			return err
		}

		req, err := http.NewRequest(http.MethodPost, url, bytes.NewBuffer(reqBytes))
		if err != nil {
			return errors.Wrap(err, "POST call failed here")
		}
		req.Header.Set("Content-Type", "application/json")

		resp, err := client.Do(req)
		if err != nil {
			return errors.Wrap(err, "PushSGXData: Error while caching Host Status Information: "+err.Error())
		}
		log.Info("response status: ", resp.StatusCode)
		log.Info("response: ", resp)
		//dec := json.NewDecoder(resp.Body)
		//dec.DisallowUnknownFields()

		//err = dec.Decode()
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return errors.Wrap(err, "POST call ioutil.ReadAll failed")
		}
		log.Info("body: ", string(body))
		resp.Body.Close()
	}
	//r.Body().Close()
	return nil
}

func validateAndSend(plugin Plugin) {
	log.Info("validateAndSend entering")
	///We will validate later
	///	generateCrd(data)

}

func addCredentialToPlugin(t1 types.Tenant, p1 Plugin, db repository.SAHDatabase) error {
	//tenantId := t1.Id
	//pluginName := p1.Name
	credential := types.TenantPluginCredential{
		TenantUUID: t1.Id,
		PluginName: p1.Name,
	}
	plugin_credential, err := db.TenantPluginCredentialRepository().Retrieve(credential)
	if err != nil {
		log.WithError(err).WithField("filter", plugin_credential).Info("failed to retrieve credentials")
		return err
	}
	///Get all the credenials from db which will come as a string.
	///This string is converted into json key value pair of type
	//configStruct := new(tenantConfig)
	credential_properties := new(Plugin)
	///configuartion is a string containing keys and values information
	//err = configStruct.GetConfigStruct(configuartion)
	err = credential_properties.GetCredentials(plugin_credential.Credential)
	if err != nil {
		log.Info("got error: ", err)
		return err
	}
	log.Info("credential_properties: ", credential_properties)
	///Now add the property array to Plugin array
	log.Info("values of plugins before credentials: ", p1)
	for _, prop := range credential_properties.Properties {
		p1.Properties = append(p1.Properties, prop)
	}
	log.Info("values of plugins after credentials: ", p1)

	return nil
}

func populateHostDetails(h1 *types.Host) (*hostDetails, error) {
	details := new(hostDetails)
	details.uuid = h1.Id
	details.hardwareUuid = h1.HardwareUUID
	details.hostname = h1.HostName

	log.Info("details: ", details)
	platformData1 := new(PlatformData)
	//var platformData1 PlatformData
	//platformData1 := &PlatformData{sgx_enabled: h1.SGXEnabled}
	platformData1.Sgx_enabled = h1.SGXEnabled
	platformData1.Sgx_supported = h1.SGXSupported
	platformData1.Flc_enabled = h1.FLCEnabled
	platformData1.TcbUpToDate = h1.TCBUpToDate
	platformData1.Epc_size = h1.EPCSize
	platformData1.Trusted = true
	platformData1.ValidTo = "2020-08-28T13:05:05.932Z"

	log.Info("platformData1: ", platformData1)
	trustReportBytes, err := (json.Marshal(platformData1))
	if err != nil {
		return nil, errors.Wrap(err, "synchAttestationInfo: Failed to get configurations")
	}
	trustReport := string(trustReportBytes)
	log.Info("trustReport: ", trustReport)
	signedTrustReport, err := createSignedTrustReport(trustReport)
	if err != nil {
		return nil, errors.Wrap(err, "synchAttestationInfo: Failed to get signed trust report")
	}
	details.trust_report = trustReport
	details.signed_trust_report = signedTrustReport ///same as details.trust_report only difference this that this signed
	return details, nil
}
