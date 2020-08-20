/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package repository

import "intel/isecl/shub/types"

type HostTenantMappingRepository interface {
	Create(types.HostTenantMapping) (*types.HostTenantMapping, error)
	Retrieve(types.HostTenantMapping) (*types.HostTenantMapping, error)
	RetrieveAll(types.HostTenantMapping) (types.HostTenantMappings, error)
	RetrieveAllActiveMappingsByTenantId(types.HostTenantMapping) (types.HostTenantMappings, error)
	Update(types.HostTenantMapping) (*types.HostTenantMapping, error)
	Delete(types.HostTenantMapping) error
}
