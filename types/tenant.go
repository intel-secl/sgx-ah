/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package types

import (
	"time"
)

// Tenant struct is the database schema of a Tenants table
type Tenant struct {
	Id          string    `json:"-" gorm:"type:uuid;unique;primary_key;"`
	TenantName  string    `json:"-"`
	TenantKey   string    `json:"-"`
	Config      string    `json:"-"`
	CreatedTime time.Time `json:"-"`
	CreatedBy   string    `json:"-"`
	UpdatedTime time.Time `json:"-"`
	UpdatedBy   string    `json:"-"`
	Deleted     bool      `json:"-" gorm:"type:bool;not null;default:false"`
}

type Tenants []Tenant
