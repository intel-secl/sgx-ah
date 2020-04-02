/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package resource

import (
	"encoding/json"
	"github.com/pkg/errors"
	"intel/isecl/sgx-attestation-hub/constants"
	"intel/isecl/sgx-attestation-hub/repository"
	"intel/isecl/sgx-attestation-hub/resource/plugins"
	"intel/isecl/sgx-attestation-hub/types"

	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"strings"

	"io/ioutil"
)

type tenantConfig struct {
	TenantId   string         `json:"id"`
	TenantName string         `json:"name"`
	Plugins    []types.Plugin `json:"plugins"`
	Deleted    bool           `json:"deleted"`
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

type Plugin1 types.Plugin
type hostDetails types.HostDetails

func (e *tenantConfig) GetConfigStruct(configuartion string) error {

	log.Trace("resource/sgx_plugin:GetConfigStruct() Entering: ")
	defer log.Trace("resource/sgx_plugin:GetConfigStruct() Leaving")

	err := json.Unmarshal(([]byte(configuartion)), e)
	if err != nil {
		return errors.Wrap(err, "configuration Unmarshal Failed")
	}
	return nil
}

func GetCredentials(configuartion string, prop *[]types.Property) error {
	log.Trace("resource/sgx_plugin:GetCredentials() Entering")
	defer log.Trace("resource/sgx_plugin:GetCredentials() Leaving")
	err := json.Unmarshal(([]byte(configuartion)), prop)
	if err != nil {
		return errors.Wrap(err, "configuration Unmarshal Failed")
	}
	return err
}

func GetAHPublicKey() []byte {
	rsaPublicKeyLocation := constants.PublickeyLocation
	pubKey, err := ioutil.ReadFile(rsaPublicKeyLocation)
	if err != nil {
		log.Error("Error in reading the hub pem file:", err)
	}
	return pubKey
}

func createSignedTrustReport(createSignedTrustReport string) (string, error) {
	log.Trace("In createSignedTrustReport")
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
	return signatureString, nil
}

func SynchAttestationInfo(db repository.SAHDatabase) error {
	log.Trace("resource/synchAttestationInfo: synchAttestationInfo() Entering")
	defer log.Trace("resource/synchAttestationInfo: synchAttestationInfo() Leaving")

	ext_tennats, err := db.TenantRepository().RetrieveAllActiveTenants()
	if ext_tennats == nil {
		log.Info("No tenants configured")
		return err
	}
	for _, tenant := range ext_tennats {
		///Read Tenant Configuration
		///Get configuration string and convert that string to corresponding key value pair
		/// get ahMapping data: getHostHardwareUuid()
		///get hosts data for the getHostHardwareUuid()
		///	populateHostDetails()
		configuartion := tenant.Config
		configStruct := new(tenantConfig)
		///configuartion is a string containing keys and values information
		err = configStruct.GetConfigStruct(configuartion)
		if err != nil {
			log.Error("synchAttestationInfo: Failed to get configurations for tenant: ", tenant.Id)
			continue
		}
		tenant_mapping, err := db.HostTenantMappingRepository().RetrieveAll(types.HostTenantMapping{TenantUUID: tenant.Id, Deleted: false})
		if err != nil {
			log.Error("synchAttestationInfo: Failed to get tenant mapping for: ", tenant.Id)
			continue
		} else if len(tenant_mapping) == 0 {
			log.Error("synchAttestationInfo: no host assigned to the tenant: ", tenant.Id)
			continue
		}
		log.Info("tenant_mapping retrieved: ", len(tenant_mapping))

		var hostDataSlice []types.HostDetails
		for _, mapping := range tenant_mapping {
			hardwareuuid := mapping.HostHardwareUUID
			host, err := db.HostRepository().Retrieve(types.Host{HardwareUUID: hardwareuuid, Deleted: false})
			if host == nil {
				//	return errors.New("No host with this uuid")
				log.Error("synchAttestationInfo: No host with this uuid: ", hardwareuuid)
				continue
			}
			hostDetailsPtr, err := populateHostDetails(host)
			if err != nil {
				log.Error("synchAttestationInfo: Failed to get configurations: ", err)
				continue
			}

			///Now add the host in a list of hosts
			hostDataSlice = append(hostDataSlice, *hostDetailsPtr)
		}
		log.Trace("Number of hosts to the tenant: ", len(hostDataSlice))
		err = processDataToPlugins(tenant, hostDataSlice, configStruct.Plugins, db)
		if err != nil {
			log.Error("synchAttestationInfo: Failed to push data: ", err)
		}
	}
	return nil
}

func processDataToPlugins(t1 types.Tenant, h1 []types.HostDetails, p1 []types.Plugin, db repository.SAHDatabase) error {
	log.Trace("resource/processDataToPlugins: processDataToPlugins() Entering")
	defer log.Trace("resource/processDataToPlugins: processDataToPlugins() Leaving")
	for _, plugin := range p1 {
		var pData types.PublishData
		pData.TenantId = t1.Id
		pData.Host_details = h1
		var value string
		for _, property := range plugin.Properties {
			if property.Key == "plugin.provider" {
				value = property.Value
				break
			}
		}
		if value == "" {
			////report error
			log.Error("value of plugin provider is null")
			return errors.New("value of plugin provider is null")
		}
		///Get Plugin class name
		err := addCredentialToPlugin(t1, &plugin, db)
		if err != nil {
			log.Error("got error while adding Credentials: ", err)
			return errors.Wrap(err, "Couldn't add credentials for plugin")
		}
		if value == "Kubernetes" {
			var k1 plugins.Kubernetes
			err := k1.Pushdata(pData, plugin)
			if err != nil {
				log.Error("got error while pushing the data: ", err)
				return err
			}
		} else if value == "OpenStack" {
		} else {
			///error
			log.Error("plugin provider doesn't match")
			return errors.New("plugin provider doesn't match")
		}
	}
	return nil
}

func addCredentialToPlugin(t1 types.Tenant, p1 *types.Plugin, db repository.SAHDatabase) error {
	credential := types.TenantPluginCredential{
		TenantUUID: t1.Id,
		PluginName: p1.Name,
	}
	plugin_credential, err := db.TenantPluginCredentialRepository().Retrieve(credential)
	if err != nil {
		log.Error("didn't find any credential for plugin of tenant id: ", t1.Id)
		return errors.Wrap(err, "didn't find any credential for plugin")
	}
	///Get all the credenials from db which will come as a string.
	///This string is converted into json key value pair of type
	var credential_properties []types.Property
	///configuartion is a string containing keys and values information
	err = GetCredentials(plugin_credential.Credential, &credential_properties)
	if err != nil {
		log.Error("couldn't get any credentials: ", err)
		return errors.Wrap(err, "couldn't get any credentials")
	}
	log.Trace("credential_properties: ", credential_properties)
	///Now add the property array to Plugin array
	for _, prop := range credential_properties {
		p1.Properties = append(p1.Properties, prop)
	}
	log.Trace("values of plugins after credentials: ", p1)
	return nil
}

func populateHostDetails(h1 *types.Host) (*types.HostDetails, error) {
	details := new(types.HostDetails)
	details.Uuid = h1.Id
	details.HardwareUuid = h1.HardwareUUID
	details.Hostname = h1.HostName

	hostPlatformData := new(PlatformData)
	hostPlatformData.Sgx_enabled = h1.SGXEnabled
	hostPlatformData.Sgx_supported = h1.SGXSupported
	hostPlatformData.Flc_enabled = h1.FLCEnabled
	hostPlatformData.TcbUpToDate = h1.TCBUpToDate
	hostPlatformData.Epc_size = h1.EPCSize
	hostPlatformData.Epc_size = strings.Replace(hostPlatformData.Epc_size, " ", "", -1) ///This is so because in K8S CRD can't have spaces
	hostPlatformData.Trusted = true
	hostPlatformData.ValidTo = "2021-08-28T13:05:05.932Z"

	log.Trace("hostPlatformData: ", hostPlatformData)
	trustReportBytes, err := (json.Marshal(hostPlatformData))
	if err != nil {
		return nil, errors.Wrap(err, "failed to marshal hostPlatformData to get trustReport")
	}
	trustReport := string(trustReportBytes)
	signedTrustReport, err := createSignedTrustReport(trustReport)
	if err != nil {
		return nil, errors.Wrap(err, "synchAttestationInfo: Failed to get signed trust report")
	}
	details.Trust_report = trustReport
	details.Signed_trust_report = signedTrustReport ///same as details.trust_report only difference this that this signed
	return details, nil
}
