-- Schema ของ plugin oidc-introspect (Kong 3.x format)
return {
  name = "oidc-introspect",
  fields = {
    { config = {
        type = "record",
        fields = {
          { introspection_url = { type = "string", required = true } },
          { client_id = { type = "string", required = true } },
          { client_secret = { type = "string", required = true } },
          { cache_ttl = { type = "number", default = 10, gt = 0 } },
        },
    } },
  },
}
