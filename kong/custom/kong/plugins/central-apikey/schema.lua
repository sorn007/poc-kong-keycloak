return {
  name = "central-apikey",
  fields = {
    { config = {
        type = "record",
        fields = {
          { validation_url = { type = "string", required = true } },
          { read_scope = { type = "string", default = "orders.read", len_min = 0 } },
          { write_scope = { type = "string", default = "orders.write", len_min = 0 } },
          { gateway_secret = { type = "string", default = "", len_min = 0 } },
          { cache_ttl = { type = "number", default = 15, gt = 0 } },
          { key_names = { type = "string", default = "apikey", len_min = 1 } },
        },
    } },
  },
}
