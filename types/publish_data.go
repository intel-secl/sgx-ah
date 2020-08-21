/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package types

type HostDetails struct {
	Uuid                string
	HardwareUuid        string
	Trust_report        string
	Hostname            string
	Signed_trust_report string
}

type PublishData struct {
	Host_details []HostDetails
	TenantId     string
}

type Property struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

type Plugin struct {
	Name       string     `json:"name,omitempty"`
	Properties []Property `json:"properties,omitempty"`
}
