/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package types

import (
	"time"
)

// TenantPluginCredential struct is the database schema of a TenantPluginCredentials table
type TenantPluginCredential struct {
	Id          string    `json:"-" gorm:"type:uuid;unique;primary_key;"`
	TenantUUID  string    `json:"-" gorm:"type:uuid"`
	PluginName  string    `json:"-"`
	TenantName  string    `json:"-"`
	Credential  string    `json:"-"`
	CreatedTime time.Time `json:"-"`
}

type TenantPluginCredentials []TenantPluginCredential
