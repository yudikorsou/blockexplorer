# The Dogecoin Core app (doge-dogecoin-core) derives its RPC password from its own app seed:
#   derive_entropy "${app_entropy_identifier}-rpc-password"
# Umbrel sets app_entropy_identifier to the app being started, so when this app starts, the
# APP_DOGECOIN_RPC_PASS from that app's exports.sh is derived from *this* app's seed instead and
# the node answers 401. Derive it again from the Dogecoin Core app's seed (app-<id>-seed).
export APP_HASHES_DOGECOIN_RPC_PASS="$(derive_entropy "app-doge-dogecoin-core-seed-rpc-password")"
