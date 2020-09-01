package docs

import "intel/isecl/shub/resource"

type PluginReq struct {
        PluginName  string             `json:"name"`
        Plugins     []*resource.Plugin `json:"plugins"`
}



// PluginReq request payload
// swagger:parameters PluginReq
type PluginReqInfo struct {
        // in:body
        Body PluginReq
}

// Tenant resposne payload
// swagger:response Tenant
type TenantInfo struct {
        // in:body
        Body resource.Tenant
}

type Tenants []resource.Tenant

// Tenants resposne payload
// swagger:response Tenants
type TenantsInfo struct {
        // in:body
        Body Tenants
}

// swagger:operation POST /tenants Tenant registerTenant
// ---
//
// description: |
//  Registers a tenant. A tenant controls SGX hosts that are managed by an orchestrator that is also under the control of the tenant. 
//  SGX Hub pushes the tenant's hosts SGX data to the tenant's orchestrator.
//  It is registered by providing tenant configuration along with plugins in the request body.
//  Supported plugin names are nova and kubernetes in the tenant configuration.
//  A valid bearer token is required to authorize this REST call.
//
// security:
//  - bearerAuth: []
// consumes:
//  - application/json
// produces:
//  - application/json
// parameters:
// - name: request body
//   required: true
//   in: body
//   schema:
//     "$ref": '#/definitions/PluginReq'
// responses:
//   '201':
//      description: Successfully registered the tenant.
//        The boolean attribute "deleted" specifies whether the tenant is present or deleted from the SGX Hub database.
//      schema:
//        "$ref": "#/definitions/Tenant"
//
// x-sample-call-endpoint: https://sgx-ah.com:14000/sgx-ah/v1/tenants
// x-sample-call-input: |
//   {
//    "name": "km-os-223",
//       "plugins": [
//       {
//              "name": "Nova",
//              "properties": [
//              {
//                      "key": "api.endpoint",
//                      "value": "http://openstack.server.com:8774"
//              },
//              {
//                      "key": "auth.endpoint",
//                      "value": "http://openstack.server.com:5000"
//              },
//              {
//                      "key": "auth.version",
//                      "value": "v2"
//              },
//              {
//                      "key": "user.name",
//                      "value": "admin"
//              },
//              {
//                      "key": "user.password",
//                      "value": "password"
//              },
//              {
//                      "key": "tenant.name",
//                      "value": "default"
//              },
//              {
//                      "key": "plugin.provider",
//                      "value": "com.intel.attestationhub.plugin.nova.NovaPluginImpl"
//              }
//              ]
//       }
//       ]
//   }
// x-sample-call-output: |
//  {
//    "id": "b182fdf4-46f3-4287-b8b7-26bc0fb3e3df",
//    "name": "km-os-223",
//    "deleted": false,
//    "plugins": [
//        {
//            "name": "Nova",
//            "properties": [
//                {
//                    "key": "api.endpoint",
//                    "value": "http://openstack.server.com:8774"
//                },
//                {
//                    "key": "auth.endpoint",
//                    "value": "http://openstack.server.com:5000"
//                },
//                {
//                    "key": "auth.version",
//                    "value": "v2"
//                },
//                {
//                    "key": "tenant.name",
//                    "value": "default"
//                },
//                {
//                    "key": "plugin.provider",
//                    "value": "com.intel.attestationhub.plugin.nova.NovaPluginImpl"
//                }
//            ]
//        }
//    ]
//  }
// ---

// swagger:operation GET /tenants Tenant queryTenants
// ---
// description: |
//   Searches for the tenant configuration based on the specified filter criteria in the SGX Hub database.
//   A valid bearer token is required to authorize this REST call.
//
// security:
//  - bearerAuth: []
// produces:
//  - application/json
// parameters:
// - name: nameEqualTo
//   description: Name of the tenant.
//   in: query
//   type: string
// responses:
//   '200':
//     description: Successfully retrieved the tenant configuration based on provided filter criteria.
//     content:
//       application/json
//     schema:
//       "$ref": "#/definitions/Tenants"
// x-sample-call-endpoint: https://sgx-ah.com:14000/sgx-ah/v1/tenants?nameEqualTo=km-os-223
// x-sample-call-output: |
//  [
//    {
//        "id": "b182fdf4-46f3-4287-b8b7-26bc0fb3e3df",
//        "name": "km-os-223",
//        "deleted": false,
//        "plugins": [
//            {
//                "name": "Nova",
//                "properties": [
//                    {
//                        "key": "api.endpoint",
//                        "value": "http://openstack.server.com:8774"
//                    },
//                    {
//                        "key": "auth.endpoint",
//                        "value": "http://openstack.server.com:5000"
//                   },
//                    {
//                        "key": "auth.version",
//                        "value": "v2"
//                    },
//                    {
//                        "key": "tenant.name",
//                        "value": "default"
//                    },
//                    {
//                        "key": "plugin.provider",
//                        "value": "com.intel.attestationhub.plugin.nova.NovaPluginImpl"
//                    }
//                ]
//            }
//        ]
//    }
//  ]
// ---


// swagger:operation DELETE /tenants/{id} Tenant deleteTenant
// ---
// description: |
//   Deletes a tenant configuration associated with the specified tenant id from the SGX Hub  database.
//   A valid bearer token is required to authorize this REST call.
//
// security:
//  - bearerAuth: []
// parameters:
// - name: id
//   description: Unique ID of the tenant.
//   in: path
//   required: true
//   type: string
//   format: uuid
// responses:
//   '204':
//     description: Successfully deleted the tenant configuration associated with the specified tenant id.
//
// x-sample-call-endpoint: |
//    https://sgx-ah.com:14000/sgx-ah/v1/tenants/30a59ee5-0475-40fb-adbf-992039cc2d0b
// x-sample-call-output: |
//    204 No content
// ---


// swagger:operation GET /tenants/{id} Tenant getTenant
// ---
// description: |
//   Retrieves the tenant configuration associated with a specified tenant id from the SGX Hub database.
//   A valid bearer token is required to authorize this REST call.
//
// security:
//  - bearerAuth: []
// produces:
//  - application/json
// parameters:
// - name: id
//   description: Unique ID of the tenant.
//   in: path
//   required: true
//   type: string
//   format: uuid
// responses:
//   '200':
//     description: Successfully retrieved the tenant configuration associated with the specified tenant id.
//     schema:
//       "$ref": "#/definitions/Tenant"
//
// x-sample-call-endpoint: |
//    https://sgx-ah.com:14000/sgx-ah/v1/tenants/b182fdf4-46f3-4287-b8b7-26bc0fb3e3df
// x-sample-call-output: |
//  {
//    "id": "b182fdf4-46f3-4287-b8b7-26bc0fb3e3df",
//    "name": "km-os-223",
//    "deleted": false,
//    "plugins": [
//        {
//            "name": "Nova",
//            "properties": [
//                {
//                    "key": "api.endpoint",
//                    "value": "http://openstack.server.com:8774"
//                },
//                {
//                    "key": "auth.endpoint",
//                    "value": "http://openstack.server.com:5000"
//                },
//                {
//                    "key": "auth.version",
//                    "value": "v2"
//                },
//                {
//                    "key": "tenant.name",
//                    "value": "default"
//                },
//                {
//                    "key": "plugin.provider",
//                    "value": "com.intel.attestationhub.plugin.nova.NovaPluginImpl"
//                }
//            ]
//        }
//    ]
//  }
// ---


// swagger:operation PUT /tenants/{id} Tenant updateTenant
// ---
//
// description: |
//   Updates a tenant configuration associated with a specified tenant id from the SGX Hub database. 
//   A valid bearer token is required to authorize this REST call.
//
// security:
//  - bearerAuth: []
// consumes:
//  - application/json
// produces:
//  - application/json
// parameters:
// - name: id
//   description: Unique ID of the tenant.
//   in: path
//   required: true
//   type: string
//   format: uuid
// - name: request body
//   required: true
//   in: body
//   schema:
//     "$ref": '#/definitions/PluginReq'
// responses:
//   '200':
//      description: Successfully updated the tenant configuration.
//      schema:
//        "$ref": "#/definitions/Tenant"
//
// x-sample-call-endpoint: https://sgx-ah.com:14000/sgx-ah/v1/tenants/b182fdf4-46f3-4287-b8b7-26bc0fb3e3df
// x-sample-call-input: |
//   {
//       "name": "km-os-223-updated",
//       "plugins": [
//       {
//              "name": "Nova",
//              "properties": [
//              {
//                      "key": "api.endpoint",
//                      "value": "http://openstack.server.com:8774"
//              },
//              {
//                      "key": "auth.endpoint",
//                      "value": "http://openstack.server.com:5000"
//              },
//              {
//                      "key": "auth.version",
//                      "value": "v2"
//              },
//              {
//                      "key": "user.name",
//                      "value": "admin"
//              },
//              {
//                      "key": "user.password",
//                      "value": "password"
//              },
//              {
//                      "key": "tenant.name",
//                      "value": "default"
//              },
//              {
//                      "key": "plugin.provider",
//                      "value": "com.intel.attestationhub.plugin.nova.NovaPluginImpl"
//              }
//              ]
//       }
//       ]
//   }
// x-sample-call-output: |
//  {
//    "id": "b182fdf4-46f3-4287-b8b7-26bc0fb3e3df",
//    "name": "km-os-223-updated",
//    "deleted": false,
//    "plugins": [
//        {
//            "name": "Nova",
//            "properties": [
//                {
//                    "key": "api.endpoint",
//                    "value": "http://openstack.server.com:8774"
//                },
//                {
//                    "key": "auth.endpoint",
//                    "value": "http://openstack.server.com:5000"
//                },
//                {
//                    "key": "auth.version",
//                    "value": "v2"
//                },
//                {
//                    "key": "tenant.name",
//                    "value": "default"
//                },
//                {
//                    "key": "plugin.provider",
//                    "value": "com.intel.attestationhub.plugin.nova.NovaPluginImpl"
//                }
//            ]
//        }
//    ]
//  }
// ---
