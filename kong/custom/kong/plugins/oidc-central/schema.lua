-- Schema ของ plugin oidc-central (Kong 3.x format)
return {
  name = "oidc-central",
  fields = {
    { config = {
        type = "record",
        fields = {
          { issuer = { type = "string", required = true } },
          { jwks_url = { type = "string", required = true } },
          { audience = { type = "string", required = true } },
          { required_scope = { type = "string", default = "", len_min = 0 } },
          { jwks_ttl = { type = "number", default = 300, gt = 0 } },
        },
    } },
  },
}
