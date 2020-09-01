package docs

import  (
	"intel/isecl/shub/resource"
        "intel/isecl/shub/types"
)

// HostTenantMappingRequest request payload
// swagger:parameters HostTenantMappingRequest
type HostTenantMappingRequestInfo struct {
        // in:body
        Body resource.HostTenantMappingRequest
}

// HostTenantMappingResponse response payload
// swagger:response HostTenantMappingResponse
type HostTenantMappingResponseInfo struct {
        // in:body
        Body resource.HostTenantMappingResponse
}

// HostTenantMapping response payload
// swagger:response HostTenantMapping
type HostTenantMappingInfo struct {
        // in:body
        Body types.HostTenantMapping
}

// HostTenantMappings response payload
// swagger:response HostTenantMappings
type HostTenantMappingsInfo struct {
        // in:body
        Body types.HostTenantMappings
}

// swagger:operation POST /host-assignments Host-assignment createHostTenantMapping
// ---
//
// description: |
//  Creates or updates a tenant to host(s) mappings by assigning the host(s) to the tenant
//  in the SGX Hub database.
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
//     "$ref": '#/definitions/HostTenantMappingRequest'
// responses:
//   '201':
//      description: Successfully created the tenant to host mapping.
//      schema:
//        "$ref": "#/definitions/HostTenantMappingResponse"
//
// x-sample-call-endpoint: https://sgx-ah.com:14000/sgx-ah/v1/host-assignments
// x-sample-call-input: |
//  {
//    "tenant_id": "b182fdf4-46f3-4287-b8b7-26bc0fb3e3df",
//    "hardware_uuids": [
//        "88888888-8887-1214-0516-3707a5a5a5a5"
//    ]
//  }
// x-sample-call-output: |
//  {
//    "mappings": [
//        {
//            "mapping_id": "16b73650-a372-43a7-af83-78b558c9a572",
//            "tenant_id": "b182fdf4-46f3-4287-b8b7-26bc0fb3e3df",
//            "hardware_uuid": "88888888-8887-1214-0516-3707a5a5a5a5"
//        }
//    ]
//  }
// ---

// swagger:operation GET /host-assignments Host-assignment queryHostTenantMappings
// ---
// description: |
//   Searches for the tenant to host(s) mappings based on the provided filter criteria in the SGX Hub database.
//   A valid bearer token is required to authorize this REST call.
//
// security:
//  - bearerAuth: []
// produces:
//  - application/json
// parameters:
// - name: host_hardware_uuid 
//   description: Hardware UUID of the host.
//   in: query
//   type: string
//   format: uuid
// - name: tenant_id
//   description: Unique UUID of the tenant.
//   in: query
//   type: string
//   format: uuid
// responses:
//   '200':
//     description: Successfully retrieved the tenant to host mapping information.
//     content:
//       application/json
//     schema:
//       "$ref": "#/definitions/HostTenantMappings"
// x-sample-call-endpoint: https://sgx-ah.com:14000/sgx-ah/v1/host-assignments?tenant_id=b182fdf4-46f3-4287-b8b7-26bc0fb3e3df
// x-sample-call-output: |
//  [
//    {
//        "id": "16b73650-a372-43a7-af83-78b558c9a572",
//        "host_hardware_uuid": "88888888-8887-1214-0516-3707a5a5a5a5",
//        "tenant_uuid": "b182fdf4-46f3-4287-b8b7-26bc0fb3e3df",
//        "created_time": "2020-06-16T08:43:46.72043Z",
//        "updated_time": "2020-06-16T08:43:46.720431Z",
//        "deleted": false
//    }
//  ]
// ---


// swagger:operation DELETE /host-assignments/{id} Host-assignment deleteTenantMapping
// ---
// description: |
//   Deletes a tenant to host mapping information associated with a specified mapping id in the SGX Hub database.
//   A valid bearer token is required to authorize this REST call.
//
// security:
//  - bearerAuth: []
// parameters:
// - name: id
//   description: Unique Mapping ID.
//   in: path
//   required: true
//   type: string
//   format: uuid
// responses:
//   '204':
//     description: Successfully deleted tenant to host mapping information.
//
// x-sample-call-endpoint: |
//    https://sgx-ah.com:14000/sgx-ah/v1/host-assignments/16b73650-a372-43a7-af83-78b558c9a572
// x-sample-call-output: |
//    204 No content
// ---


// swagger:operation GET /host-assignments/{id} Host-assignment getHostTenantMapping
// ---
// description: |
//   Retrieves a tenant to host mapping information associated with a specified mapping id from the SGX Hub database.
//   A valid bearer token is required to authorize this REST call.
//
// security:
//  - bearerAuth: []
// produces:
//  - application/json
// parameters:
// - name: id
//   description: Unique Mapping ID.
//   in: path
//   required: true
//   type: string
//   format: uuid
// responses:
//   '200':
//     description: Successfully retrieved the tenant to host mapping information.
//     schema:
//       "$ref": "#/definitions/HostTenantMapping"
//
// x-sample-call-endpoint: |
//    https://sgx-ah.com:14000/sgx-ah/v1/host-assignments/16b73650-a372-43a7-af83-78b558c9a572
// x-sample-call-output: |
//  {
//    "id": "16b73650-a372-43a7-af83-78b558c9a572",
//    "host_hardware_uuid": "88888888-8887-1214-0516-3707a5a5a5a5",
//    "tenant_uuid": "b182fdf4-46f3-4287-b8b7-26bc0fb3e3df",
//    "created_time": "2020-06-16T08:43:46.72043Z",
//    "updated_time": "2020-06-16T08:43:46.720431Z",
//    "deleted": false
//  }
// ---
