/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package mock

import (
	"intel/isecl/shub/types"
)

type MockHostTenantMappingRepository struct {
	CreateFunc      func(types.HostTenantMapping) (*types.HostTenantMapping, error)
	RetrieveFunc    func(types.HostTenantMapping) (*types.HostTenantMapping, error)
	RetrieveAllFunc func(types.HostTenantMapping) (types.HostTenantMappings, error)
	UpdateFunc      func(types.HostTenantMapping) error
	DeleteFunc      func(types.HostTenantMapping) error
}

func (m *MockHostTenantMappingRepository) Create(ht types.HostTenantMapping) (*types.HostTenantMapping, error) {
	if m.CreateFunc != nil {
		return m.CreateFunc(ht)
	}
	return nil, nil
}

func (m *MockHostTenantMappingRepository) Retrieve(ht types.HostTenantMapping) (*types.HostTenantMapping, error) {
	if m.RetrieveFunc != nil {
		return m.RetrieveFunc(ht)
	}
	return nil, nil
}

func (m *MockHostTenantMappingRepository) RetrieveAll(ht types.HostTenantMapping) (types.HostTenantMappings, error) {
	if m.RetrieveAllFunc != nil {
		return m.RetrieveAllFunc(ht)
	}
	return nil, nil
}

func (m *MockHostTenantMappingRepository) Update(ht types.HostTenantMapping) error {
	if m.UpdateFunc != nil {
		return m.UpdateFunc(ht)
	}
	return nil
}

func (m *MockHostTenantMappingRepository) Delete(ht types.HostTenantMapping) error {
	if m.DeleteFunc != nil {
		return m.DeleteFunc(ht)
	}
	return nil
}
