/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package resource

import (
	"fmt"
	"github.com/pkg/errors"
	"intel/isecl/lib/clients/v3"
	"intel/isecl/lib/clients/v3/aas"
	"intel/isecl/shub/config"
	"intel/isecl/shub/constants"
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
	jwtToken, err := aasClient.GetUserToken(c.SHUB.User)
	aasRWLock.RUnlock()
	// something wrong
	if err != nil {
		// lock aas with w lock
		aasRWLock.Lock()
		defer aasRWLock.Unlock()
		// check if other thread fix it already
		jwtToken, err = aasClient.GetUserToken(c.SHUB.User)
		// it is not fixed
		if err != nil {
			aasClient.AddUser(c.SHUB.User, c.SHUB.Password)
			err = aasClient.FetchAllTokens()
			jwtToken, err = aasClient.GetUserToken(c.SHUB.User)
			if err != nil {
				return errors.Wrap(err, "resource/utils:addJWTToken() Could not fetch token")
			}
		}
	}
	log.Debug("resource/utils:addJWTToken() successfully added jwt bearer token")
	req.Header.Set("Authorization", "Bearer "+string(jwtToken))
	return nil
}

func getApi(requestType string, url string) (*http.Response, error) {

	client, err := clients.HTTPClientWithCADir(constants.TrustedCAsStoreDir)
	if err != nil {
		return nil, errors.Wrap(err, "getApi : Error in getting client object")
	}

	req, err := http.NewRequest(requestType, url, nil)
	if err != nil {
		return nil, errors.Wrap(err, "getApi: Failed to Get New request")
	}
	req.Header.Set("Accept", "application/json")

	err = addJWTToken(req)
	if err != nil {
		return nil, errors.Wrap(err, "resource/utils: getApi() Failed to add JWT token")
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, errors.Wrap(err, "resource/utils: getApi() Error from response")
	}
	log.Debug("FetchAllHostsFromHVS: Status: ", resp.StatusCode)

	if resp.StatusCode == http.StatusUnauthorized {
		// fetch token and try again
		aasRWLock.Lock()
		aasClient.FetchAllTokens()
		aasRWLock.Unlock()
		err = addJWTToken(req)
		if err != nil {
			return nil, errors.Wrap(err, "resource/utils: getApi() Failed to add JWT token")
		}
		resp, err = client.Do(req)
		if err != nil {
			return nil, errors.Wrap(err, "resource/utils: getApi() Error from response")
		}
	}

	if resp.StatusCode != http.StatusOK {
		return nil, errors.Wrapf(err, "resource/utils: getApi() Invalid status code received:%d", resp.StatusCode)
	}
	return resp, nil
}

func WriteDataIn(fileName string, data string) error {

	destination, err := os.Create(fileName)
	if err != nil {
		return errors.Wrap(err, "Error while creating file")
	}
	// Below fmt.Fprintf is use to write the data into file.
	fmt.Fprintf(destination, "%s", data)
	if err = destination.Close(); err != nil {
		return errors.Wrap(err, "Error while closing file")
	}
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
