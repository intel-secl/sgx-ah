/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package plugins

import (
	"bytes"
	"encoding/json"
	"github.com/pkg/errors"
	"intel/isecl/sgx-attestation-hub/constants"
	"intel/isecl/sgx-attestation-hub/types"
	"intel/isecl/sgx-attestation-hub/utils"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
)

type OpenStack struct{}

type openStack1 struct {
	Traits []string `json:"traits"`
}

type TokenResponse struct {
	Token token `json:"token"`
}

type token struct {
	Catalog []catalog `json:"catalog"`
}

type catalog struct {
	Type     string      `json:"type"`
	Endpoint []endpoints `json:"endpoints"`
}

type endpoints struct {
	Url       string `json:"url"`
	Interface string `json:"interface"`
}

type resourceProviderArr struct {
	Uuid       string `json:"uuid"`
	Generation int    `json:"generation"`
}

type resourceProviders struct {
	ResourceProvider []resourceProviderArr `json:"resource_providers"`
}

type traitsInfo struct {
	Generation int      `json:"resource_provider_generation"`
	Traits     []string `json:"traits"`
}

type ResourceProviderTraits struct {
	Traits      []string
	ResourceArr resourceProviderArr
}

func (e *OpenStack) Pushdata(pData types.PublishData, plugin types.Plugin) error {
	log.Trace("resource/plugin OpenStackPlugin Pushdata() entering")
	defer log.Trace("resource/plugin OpenStackPlugin:Pushdata() Leaving")

	/*        NovaRsClient novaRsClient = NovaRsClientBuilder.build(plugin);
			1) get all plugin properies
			2) Calls  with this information to PlacementClient ->validates keystonePublicEndpoint, Calls initIdentityService -> cretaes a token used to contact OpenStack(File AbstractIdentityService.java)
		3)call to sendDataToEndpoint() -> NovaRsClient.java
	4) Creates Traits and send them

	*/

	if len(plugin.Properties) == 0 {
		log.Error("No configuration provided ")
		errors.New("plugin properties missing")
	}

	var pluginAuthEndpoint, domainName, password, userName, tenantName string

	for _, property := range plugin.Properties {
		///TODO: Turn this into swtich case
		if property.Key == "auth.endpoint" {
			pluginAuthEndpoint = property.Value
		} else if property.Key == "domain.name" {
			domainName = property.Value
		} else if property.Key == "user.password" {
			password = property.Value
		} else if property.Key == "user.name" {
			userName = property.Value
		} else if property.Key == "tenant.name" {
			tenantName = property.Value
		}
	}
	if pluginAuthEndpoint == "" || domainName == "" || userName == "" || password == "" || tenantName == "" {
		log.Error("Configuration not provided")
		return errors.New("configurations missing")
	}
	///Now use above information to cretae  a token and send to OpenStack
	err := validateUrl(pluginAuthEndpoint, "AUTH")
	if err != nil {
		log.WithError(err).Info("URL parsing failed")
		return errors.Wrap(err, "URL parsing failed")
	}
	tokenUrl := pluginAuthEndpoint + constants.RESOURCE_PATH_V3_AUTH_TOKEN

	var token utils.AuthToken
	token.Auth.Identity.Methods = []string{"password"}
	token.Auth.Identity.Pass.User.Name = userName
	token.Auth.Identity.Pass.User.Domain.Name = domainName
	token.Auth.Identity.Pass.User.Password = password
	token.Auth.Scope.Project.Name = tenantName
	token.Auth.Scope.Project.Domain.Name = domainName
	tokenResponse, err := utils.CreateToken(token, tokenUrl)

	hostCustomTraitsMap := make(map[string][]string)
	var customTraitsSuperSet []string
	for _, p1 := range pData.Host_details {
		customTraits, err := generateTraitsFromTrustReport(p1)
		log.Debug("customTraits: ", customTraits)
		if err != nil {
			return errors.Wrap(err, "error came in generateTraitsFromTrustReportgenerateTraitsFromTrustReport")
		}
		customTraitsSuperSet = append(customTraitsSuperSet, customTraits...)
		hostCustomTraitsMap[p1.Hostname] = customTraits
	}
	openstackTraits, err := getOpenstackTraits(tokenResponse)
	if err != nil {
		log.WithError(err).Info("error came in getOpenstackTraits")
		return errors.Wrap(err, "error came in getOpenstackTraits")
	}
	newTraits := utils.Difference(customTraitsSuperSet, openstackTraits)
	log.Debug("newTraits: ", newTraits)
	err = createOpenstackTraits(newTraits, tokenResponse)
	if err != nil {
		log.WithError(err).Info("error came in createOpenstackTraits")
		return errors.Wrap(err, "error came in createOpenstackTraits")
	}

	///for each entry in hostCustomTraitsMap, make connection and push data
	for key, value := range hostCustomTraitsMap {
		hostName := key
		latestCitTraits := value
		log.Debug("HostName:  %s :Traits: %s", hostName, latestCitTraits)
		var hostRp resourceProviderArr
		err := getResourceProvider(hostName, tokenResponse, &hostRp)
		if err != nil {
			log.WithError(err).Info("error came in getResourceProvider")
			return errors.Wrap(err, "error came in getResourceProvider")
		}
		log.Debug("hostRp: ", hostRp.Uuid)
		if hostRp.Uuid != "" {
			mapHostTraits(hostRp.Uuid, hostName, latestCitTraits, constants.MAX_RETRIES_DUE_TO_CONFLICTS, tokenResponse)
		} else {
			log.Trace("no resource for hostname: ", hostName)
		}
	}
	return nil
}

func mapHostTraits(uuid string, hostName string, latestCitTraits []string, x int, v1 utils.TokenResponse) error {
	tries := x
	for tries > 0 {
		hostTraits, err := getResourceProviderTraits(uuid, v1)
		if err != nil {
			log.WithError(err).Info("getResourceProviderTraits failed. Retrying")
			tries--
		}
		if tries == 0 {
			log.Debug("Sending data to controller failed")
			return errors.New("error came in sending data")
		}
		log.Debug("hostTraits: ", hostTraits.Traits)
		updatedTraits, err := getUpdatedTraits(hostTraits.Traits, latestCitTraits)
		log.Debug("updatedTraits: ", updatedTraits)
		if updatedTraits != nil || err != nil {
			//create a struct
			var resourceProviderTraits ResourceProviderTraits
			resourceProviderTraits.Traits = updatedTraits
			resourceProviderTraits.ResourceArr.Uuid = hostTraits.ResourceArr.Uuid
			resourceProviderTraits.ResourceArr.Generation = hostTraits.ResourceArr.Generation
			err = mapResourceProviderTraits(resourceProviderTraits, v1)
			if err != nil {
				log.WithError(err).Info("mapResourceProviderTraits failed")
			}
			log.Info("Updating traits for host {} succeeded with {} retries", hostName, x)
		} else {
			log.Info("Skipping nova call since the host is already associated with the ISECL traits", hostName)
		}
		break
	}
	return nil
}

func mapResourceProviderTraits(resourceProviderTraits ResourceProviderTraits, v1 utils.TokenResponse) error {
	resourceUrl := utils.GetEndPointUrl(v1, constants.PLACEMENT)
	resourceUrl = resourceUrl + constants.RESOURCE_PATH_RESOURCE_PROVIDERS + resourceProviderTraits.ResourceArr.Uuid + constants.RESOURCE_PATH_TRAITS
	log.Debug("url to get resource traits: ", resourceUrl)
	var rpTraitsMapping traitsInfo
	rpTraitsMapping.Traits = resourceProviderTraits.Traits
	rpTraitsMapping.Generation = resourceProviderTraits.ResourceArr.Generation
	reqBytes, err := json.Marshal(rpTraitsMapping)
	if err != nil {
		return errors.Wrap(err, "error came in Marshalling Traits data")
	}

	req, err := putRequest(resourceUrl, v1.TokenVal, reqBytes)
	if err != nil {
		return errors.Wrap(err, "http NewRequest failed")
	}

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return errors.Wrap(err, "response is not provided: ")
	}
	log.Debug("PUT response status: ", resp.StatusCode)
	_, err = ioutil.ReadAll(resp.Body)
	if err != nil || resp.StatusCode != http.StatusOK {
		return errors.Wrap(err, "PUT call ioutil.ReadAll failed")
	}
	resp.Body.Close()
	return nil
}

func getUpdatedTraits(resourceProviderTraits []string, citTraits []string) ([]string, error) {
	log.Trace("entering getUpdatedTraits")
	commonTraits := utils.Intersection(resourceProviderTraits, citTraits)
	newTraitsToAdd := utils.Difference(citTraits, commonTraits)
	x1 := utils.Difference(resourceProviderTraits, commonTraits)
	var staleTraitsOnHost []string
	for _, a1 := range x1 {
		if strings.HasPrefix(a1, "CUSTOM_SKC") == true {
			staleTraitsOnHost = append(staleTraitsOnHost, a1)
		}
	}
	var updatedTraits []string
	if newTraitsToAdd != nil || staleTraitsOnHost != nil {
		updatedTraits = append(updatedTraits, resourceProviderTraits...)
		for i := 0; i < len(updatedTraits); i++ {
			for _, a2 := range staleTraitsOnHost {
				if a2 == updatedTraits[i] { ///If the stale content exists
					///delete it
					updatedTraits = append(updatedTraits[:i], updatedTraits[i+1:]...)
				}
			}
		}
		updatedTraits = append(updatedTraits, newTraitsToAdd...)
	}
	return updatedTraits, nil
}

func getResourceProviderTraits(uuid string, v1 utils.TokenResponse) (ResourceProviderTraits, error) {
	var resourceProviderTraitSet []string
	resourceUrl := utils.GetEndPointUrl(v1, constants.PLACEMENT)
	resourceUrl = resourceUrl + constants.RESOURCE_PATH_RESOURCE_PROVIDERS + uuid + constants.RESOURCE_PATH_TRAITS
	req, err := getRequest(resourceUrl, v1.TokenVal)
	if err != nil {
		return ResourceProviderTraits{}, errors.Wrap(err, "http NewRequest failed")
	}

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		return ResourceProviderTraits{}, errors.Wrap(err, "client.Do failed")
	}

	// Read the response body
	defer resp.Body.Close()
	if resp.Body == nil {
		return ResourceProviderTraits{}, errors.New("nothing returned from openstack")
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return ResourceProviderTraits{}, errors.Wrap(err, "error came in ioutil.ReadAll")
	}
	var r1 traitsInfo
	err = json.Unmarshal(body, &r1)
	if err != nil {
		return ResourceProviderTraits{}, errors.Wrap(err, "error came in unmarshalling")
	}
	if len(r1.Traits) == 0 {
		return ResourceProviderTraits{}, errors.Wrap(err, "error came in Traits length")
	}
	resourceProviderTraitSet = r1.Traits
	var rTraits ResourceProviderTraits
	rTraits.Traits = resourceProviderTraitSet
	rTraits.ResourceArr.Uuid = uuid
	rTraits.ResourceArr.Generation = r1.Generation
	return rTraits, nil
}

func getResourceProvider(hostName string, v1 utils.TokenResponse, r2 *resourceProviderArr) error {
	resourceUrl := utils.GetEndPointUrl(v1, constants.PLACEMENT)
	resourceUrl = resourceUrl + constants.RESOURCE_PATH_RESOURCE_PROVIDERS_NAME_QUERY + hostName
	req, err := getRequest(resourceUrl, v1.TokenVal)
	if err != nil {
		return errors.Wrap(err, "http NewRequest failed")
	}

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		return errors.Wrap(err, "client.Do failed")
	}

	// Read the response body
	defer resp.Body.Close()
	if resp.Body == nil {
		return errors.New("nothing returned from openstack")
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return errors.Wrap(err, "error came in ioutil.ReadAll")
	}
	var r1 resourceProviders
	err = json.Unmarshal(body, &r1)
	if err != nil {
		return errors.Wrap(err, "error came in unmarshalling")
	}
	if len(r1.ResourceProvider) == 0 {
		return nil
	}
	if r1.ResourceProvider != nil {
		*r2 = r1.ResourceProvider[0]
	}
	return nil
}

func createOpenstackTraits(traitsSet []string, v1 utils.TokenResponse) error {
	taritsUrl := utils.GetEndPointUrl(v1, constants.PLACEMENT)
	taritsUrl = taritsUrl + constants.RESOURCE_PATH_TRAITS

	for _, trait := range traitsSet {
		url := taritsUrl + "/" + trait
		log.Debug("Creating Trait using Url : " + url)
		req, err := putRequest(url, v1.TokenVal, nil)
		if err != nil {
			return errors.Wrap(err, "http NewRequest failed")
		}

		client := &http.Client{}
		if err != nil {
			return errors.Wrap(err, "http NewRequest failed")
		}
		resp, err := client.Do(req)
		log.Debug("status: ", resp.StatusCode)
		if err != nil || resp.StatusCode != http.StatusNoContent {
			return errors.Wrap(err, "client.Do failed")
		}
	}
	return nil
}

func getOpenstackTraits(v1 utils.TokenResponse) ([]string, error) {
	taritsUrl := utils.GetEndPointUrl(v1, constants.PLACEMENT)
	taritsUrl = taritsUrl + constants.RESOURCE_PATH_TRAITS

	req, err := getRequest(taritsUrl, v1.TokenVal)
	if err != nil {
		return nil, errors.Wrap(err, "http NewRequest failed")
	}

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		return nil, errors.Wrap(err, "client.Do failed")
	}

	// Read the response body
	defer resp.Body.Close()
	if resp.Body == nil {
		return nil, errors.New("nothing returned from openstack")
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, errors.Wrap(err, "error came in ioutil.ReadAll")
	}
	var traits openStack1
	err = json.Unmarshal(body, &traits)
	if err != nil {
		return nil, errors.Wrap(err, "error came in unmarshalling")
	}
	return traits.Traits, nil
}

func generateTraitsFromTrustReport(t1 types.HostDetails) ([]string, error) {
	//tagPrefix := Constants.CIT_TRAIT_PREFIX + Constants.AT_PREFIX
	//featurePrefix := Constants.CIT_TRAIT_PREFIX + Constants.HAS_PREFIX
	var traitSet []string
	if t1.Trust_report == "" {
		return nil, errors.New("trust report is empty")
	}
	var pData PlatformData
	err := json.Unmarshal(([]byte(t1.Trust_report)), &pData)
	if err != nil {
		return nil, errors.Wrap(err, "configuration Unmarshal Failed")
	}
	if pData.Sgx_enabled == true {
		traitSet = append(traitSet, "CUSTOM_SKC_SGX_ENABLED")
	} else {
		traitSet = append(traitSet, "CUSTOM_SKC_SGX_DISABLED")
	}
	if pData.Sgx_supported == true {
		traitSet = append(traitSet, "CUSTOM_SKC_SGX_SUPPORTED")
	} else {
		traitSet = append(traitSet, "CUSTOM_SKC_SGX_UNSUPPORTED")
	}
	if pData.TcbUpToDate == true {
		traitSet = append(traitSet, "CUSTOM_SKC_SGX_TCBUPTODATE")
	} else {
		traitSet = append(traitSet, "CUSTOM_SKC_SGX_TCBNOTUPTODATE")
	}
	if pData.Epc_size != "" {
		traitSet = append(traitSet, "CUSTOM_SKC_SGX_EPC_SIZE"+pData.Epc_size)
	} else {
		traitSet = append(traitSet, "CUSTOM_SKC_SGX_EPC_SIZE_UNAVAILABLE")
	}
	if pData.Flc_enabled == true {
		traitSet = append(traitSet, "CUSTOM_SKC_FLC_ENABLED")
	} else {
		traitSet = append(traitSet, "CUSTOM_SKC_FLC_DISABLED")
	}

	return traitSet, nil
}

func validateUrl(urlStr, typeurl string) error {
	url, err := url.Parse(urlStr)
	if err != nil {
		return errors.Wrap(err, "URL parsing failed")
	}
	if url.Hostname() == "" {
	}
	if url.Scheme == "" {
	}
	if url.Port() == "" {
	}
	return nil
}

func getRequest(urlstr, tokenVal string) (*http.Request, error) {
	url, err := url.Parse(urlstr)
	log.Debug("Getting All Traits from Nova: ", url)
	req, err := http.NewRequest("GET", url.String(), nil)
	if err != nil {
		return nil, errors.Wrap(err, "http NewRequest failed")
	}
	req.Header.Set("X-AUTH-TOKEN", tokenVal)
	req.Header.Set(constants.OPENSTACK_API_MICROVERSION_HEADER, constants.PLACEMENT_API_MICROVERSION_VALUE)
	req.Header.Set("Accept", "application/json")
	return req, nil
}

func putRequest(urlstr, tokenVal string, reqBytes []byte) (*http.Request, error) {
	url, err := url.Parse(urlstr)
	log.Debug("Adding All Traits into Nova: ", url)
	req, err := http.NewRequest("PUT", url.String(), bytes.NewBuffer(reqBytes))
	if err != nil {
		return nil, errors.Wrap(err, "http NewRequest failed")
	}
	req.Header.Set("X-AUTH-TOKEN", tokenVal)
	req.Header.Set(constants.OPENSTACK_API_MICROVERSION_HEADER, constants.PLACEMENT_API_MICROVERSION_VALUE)
	req.Header.Set("Accept", "application/json")
	return req, nil
}
