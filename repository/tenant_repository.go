/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package repository

import "intel/isecl/shub/types"

type TenantRepository interface {
	Create(types.Tenant) (*types.Tenant, error)
	Retrieve(types.Tenant) (*types.Tenant, error)
	RetrieveAll(types.Tenant) (types.Tenants, error)
	RetrieveAllActiveTenants() (types.Tenants, error)
	Update(types.Tenant) (*types.Tenant, error)
	Delete(types.Tenant) error
}
