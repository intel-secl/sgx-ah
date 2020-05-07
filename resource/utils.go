/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package resource

import (
	"fmt"
	"github.com/pkg/errors"
	"intel/isecl/lib/clients/v2"
	"intel/isecl/lib/clients/v2/aas"
	"intel/isecl/sgx-attestation-hub/config"
	"intel/isecl/sgx-attestation-hub/constants"
	"io"
	"net/http"
	"os"
	"sync"
)

var (
	c         = config.Global()
	aasClient = aas.NewJWTClient(c.AuthServiceUrl)
	aasRWLock = sync.RWMutex{}
)

func init() {
	aasRWLock.Lock()
	defer aasRWLock.Unlock()
	if aasClient.HTTPClient == nil {
		c, err := clients.HTTPClientWithCADir(constants.TrustedCAsStoreDir)
		if err != nil {
			return
		}
		aasClient.HTTPClient = c
	}
}

func addJWTToken(req *http.Request) error {
	log.Trace("resource/utils:addJWTToken() Entering")
	defer log.Trace("resource/utils:addJWTToken() Leaving")

	if aasClient.BaseURL == "" {
		aasClient = aas.NewJWTClient(c.AuthServiceUrl)
		if aasClient.HTTPClient == nil {
			c, err := clients.HTTPClientWithCADir(constants.TrustedCAsStoreDir)
			if err != nil {
				return errors.Wrap(err, "resource/utils:addJWTToken() Error initializing http client")
			}
			aasClient.HTTPClient = c
		}
	}
	aasRWLock.RLock()
	jwtToken, err := aasClient.GetUserToken(c.SAH.User)
	aasRWLock.RUnlock()
	// something wrong
	if err != nil {
		// lock aas with w lock
		aasRWLock.Lock()
		defer aasRWLock.Unlock()
		// check if other thread fix it already
		jwtToken, err = aasClient.GetUserToken(c.SAH.User)
		// it is not fixed
		if err != nil {
			aasClient.AddUser(c.SAH.User, c.SAH.Password)
			err = aasClient.FetchAllTokens()
			jwtToken, err = aasClient.GetUserToken(c.SAH.User)
			if err != nil {
				return errors.Wrap(err, "resource/utils:addJWTToken() Could not fetch token")
			}
		}
	}
	log.Debug("resource/utils:addJWTToken() successfully added jwt bearer token")
	req.Header.Set("Authorization", "Bearer "+string(jwtToken))
	return nil
}

func GetApi(requestType string, url string) (*http.Response, error) {

	client, err := clients.HTTPClientWithCADir(constants.TrustedCAsStoreDir)
	if err != nil {
		return nil, errors.Wrap(err, "GetApi : Error in getting client object")
	}

	req, err := http.NewRequest(requestType, url, nil)
	if err != nil {
		return nil, errors.Wrap(err, "GetApi: Failed to Get New request")
	}
	req.Header.Set("Accept", "application/json")

	err = addJWTToken(req)
	if err != nil {
		return nil, errors.Wrap(err, "resource/utils: GetApi() Failed to add JWT token")
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, errors.Wrap(err, "GetApi: Error while caching Host Status Information: "+err.Error())
	}
	log.Debug("FetchAllHostsFromHVS: Status: ", resp.StatusCode)

	if resp.StatusCode != http.StatusOK {
		return nil, errors.New(fmt.Sprintf("GetApi: Invalid status code received:%d", resp.StatusCode))
	}
	return resp, nil
}

func WriteDataIn(fileName string, data string) error {

	destination, err := os.Create(fileName)
	if err != nil {
		log.Debug("os.Create:", err)
		return err
	}
	defer destination.Close()
	// Below fmt.Fprintf is use to write the data into file.
	fmt.Fprintf(destination, "%s", data)
	return err
}

func ReadFileFrom(fileName string) (string, error) {

	f, err := os.Open(fileName)
	if err != nil {
		log.Debug("error opening %s: %s", fileName, err)
		return "", err
	}
	defer f.Close()

	buf := make([]byte, 50)
	if _, err := io.ReadFull(f, buf); err != nil {
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
	}
	return string(buf), err
}

func FileExists(FileName string) (bool, error) {

	if _, err := os.Stat(FileName); err == nil {
		log.Debug("File exists: ", FileName)
		return true, err
	} else {
		log.Debug("File does not exist: ", FileName)
		return false, err
	}
}
