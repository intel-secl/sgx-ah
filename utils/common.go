/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package utils

import (
	"bytes"
	"encoding/json"
	"github.com/pkg/errors"
	clog "intel/isecl/lib/common/v3/log"
	"intel/isecl/shub/constants"
	"io/ioutil"
	"net/http"
	"net/url"
	"strconv"
)

var log = clog.GetDefaultLogger()

type AuthToken struct {
	Auth Authentication `json:"auth"`
}
type Authentication struct {
	Identity identity `json:"identity"`
	Scope    Scope    `json:"scope"`
}

type project struct {
	Name   string `json:"name"`
	Domain domain `json:"domain"`
}

type Scope struct {
	Project project `json:"project"`
}
type domain struct {
	Name string `json:"name"`
}
type identity struct {
	Methods []string `json:"methods"`
	Pass    password `json:"password"`
}

type user struct {
	Name     string `json:"name"`
	Domain   domain `json:"domain"`
	Password string `json:"password"`
}

type password struct {
	User user `json:"user"`
}

type TokenResponse struct {
	Token    token `json:"token"`
	TokenVal string
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

func CreateToken(token AuthToken, tokenUrl string) (TokenResponse, error) {
	log.Trace("utils/common: CreateToken() Entering")
	defer log.Trace("utils/common: CreateToken() Leaving")

	url, err := url.Parse(tokenUrl)
	if err != nil {
		return TokenResponse{}, errors.Wrap(err, "URL parsing failed")
	}

	client := &http.Client{}
	reqBytes, err := json.Marshal(token)
	if err != nil {
		return TokenResponse{}, errors.Wrap(err, "error came in Marshalling token")
	}
	req, err := http.NewRequest(http.MethodPost, url.String(), bytes.NewBuffer(reqBytes))
	if err != nil {
		return TokenResponse{}, errors.Wrap(err, "POST call failed")
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return TokenResponse{}, errors.Wrap(err, "CreateToken: Client call failed: "+err.Error())
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		return TokenResponse{}, errors.New("CreateToken: Invalid status code received" + strconv.Itoa(resp.StatusCode))
	}
	tokenHeader := resp.Header.Get(constants.KEYSTONE_AUTH_TOKEN_HEADER_KEY)
	if tokenHeader == "" {
		return TokenResponse{}, errors.New("CreateToken: token header not found")
	}
	log.Info("tokenHeader: ", tokenHeader)

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return TokenResponse{}, errors.Wrap(err, "CreateToken: error while reading response body")
	}
	var tResp TokenResponse
	err = json.Unmarshal(body, &tResp)
	if err != nil {
		return TokenResponse{}, errors.Wrap(err, "CreateToken: error while unmarshalling token body")
	}
	var t1 TokenResponse
	t1.Token = tResp.Token
	t1.TokenVal = tokenHeader
	return t1, nil
}

func GetEndPointUrl(v1 TokenResponse, typeVar string) string {
	log.Trace("utils/common: GetEndPointUrl() Entering")
	defer log.Trace("utils/common: GetEndPointUrl() Leaving")

	var url1 string
	if v1.Token.Catalog != nil {
		for _, c1 := range v1.Token.Catalog {
			var count int
			if typeVar == c1.Type && c1.Endpoint != nil {
				for _, e1 := range c1.Endpoint {
					url1 = e1.Url
					break
					count = 1
				}
				if count == 1 {
					break
				}
			}
		}

	}
	log.Info("url: ", url1)
	return url1
}
