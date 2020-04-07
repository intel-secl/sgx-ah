/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package resource

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"github.com/pkg/errors"
	"net/http"

	cos "intel/isecl/lib/common/os"
	"intel/isecl/sgx-attestation-hub/constants"
	"io"
	"os"
)

func GetApi(requestType string, url string, bearerToken string) (*http.Response, error) {

	client := &http.Client{}

	req, err := http.NewRequest(requestType, url, nil)
	if err != nil {
		return nil, errors.Wrap(err, "GetApi: Failed to Get New request")
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+bearerToken)
	resp, err := client.Do(req)
	if err != nil {
		return nil, errors.Wrap(err, "GetApi: Error while caching Host Status Information: "+err.Error())
	}
	log.Debug("FetchAllHostsFromHVS: Status: ", resp.StatusCode)

	if resp.StatusCode != http.StatusOK {
		return nil, errors.New(fmt.Sprintf("GetApi: Invalid status code received:%d", resp.StatusCode, resp.Body, resp))
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
