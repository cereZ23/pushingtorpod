#!/usr/bin/env bash
#
# Download free GeoIP databases (db-ip.com Lite) in MaxMind .mmdb format.
#
# db-ip.com publishes CC-BY-4.0 free databases with monthly updates at
#   https://download.db-ip.com/free/dbip-city-lite-YYYY-MM.mmdb.gz
#   https://download.db-ip.com/free/dbip-asn-lite-YYYY-MM.mmdb.gz
#
# They are binary-compatible with the maxminddb reader, so no code change
# is required: the files are dropped into data/geoip/ and the network_intel
# service picks them up on next worker start.
#
# Usage:
#   scripts/download_geoip.sh [DATA_DIR]
#
# Default DATA_DIR = ./data/geoip (relative to repo root).

set -euo pipefail

DATA_DIR="${1:-./data/geoip}"
mkdir -p "${DATA_DIR}"

# db-ip publishes databases on the 1st of each month; if the current month's
# file is not yet published, fall back to the previous month.
try_download() {
    local kind="$1"        # "city" or "asn"
    local out_name="$2"    # "GeoLite2-City.mmdb" or "GeoLite2-ASN.mmdb"
    local year month url tmp

    for offset in 0 1 2; do
        year=$(date -u -d "-${offset} month" +%Y 2>/dev/null || date -u -v-${offset}m +%Y)
        month=$(date -u -d "-${offset} month" +%m 2>/dev/null || date -u -v-${offset}m +%m)
        url="https://download.db-ip.com/free/dbip-${kind}-lite-${year}-${month}.mmdb.gz"
        tmp="${DATA_DIR}/${out_name}.gz"

        echo "[geoip] trying ${url}"
        if curl -fsSL --connect-timeout 10 --max-time 300 -o "${tmp}" "${url}"; then
            gunzip -f "${tmp}"
            mv "${DATA_DIR}/${out_name%.mmdb}.mmdb" "${DATA_DIR}/${out_name}" 2>/dev/null || true
            # db-ip archives unpack to dbip-{kind}-lite-YYYY-MM.mmdb; normalize the name.
            local extracted
            extracted=$(ls "${DATA_DIR}"/dbip-${kind}-lite-*.mmdb 2>/dev/null | head -1 || true)
            if [[ -n "${extracted}" ]]; then
                mv -f "${extracted}" "${DATA_DIR}/${out_name}"
            fi
            echo "[geoip] installed ${DATA_DIR}/${out_name}"
            return 0
        fi
    done

    echo "[geoip] ERROR: could not download ${kind} database from db-ip.com" >&2
    return 1
}

try_download "city" "GeoLite2-City.mmdb"
try_download "asn"  "GeoLite2-ASN.mmdb"

echo "[geoip] done. Restart the worker container to pick up the new databases."
