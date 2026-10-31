# OpenAPI sources

The numbered fragments form one YAML document in `briqyard_api::OPENAPI`:

- `00-routes.fragment.yaml`: routes, security and parameter definitions.
- `10-machines.fragment.yaml`: machine, request, probe and process schemas.
- `20-hosts.fragment.yaml`: namespace, gateway, capacity, event and host schemas.

The daemon serves the assembled document at `/v1/openapi.yaml`.
Fragments retain their document indentation. Add a schema to its existing group; do not copy
the assembled document into another source file. Concatenate the three numbered files in
order when an external tool needs a local YAML file.
