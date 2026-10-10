#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 esp-claw contributors
# SPDX-License-Identifier: Apache-2.0
#
# One-time USB migration of an esp32_S3_DevKitC_1 from partitions_8MB.csv (one app slot + system
# partition) to partitions_8MB_ota.csv (two OTA slots), keeping NVS (settings) and the storage
# partition (/fatfs). Run from an ESP-IDF v5.5.4 shell after building edge_agent for the board:
#
#   tools/migrate_ota_layout.sh -p /dev/ttyUSB0 [-b 460800] [-d application/edge_agent/build]
#
# 1. backs up the whole 8 MB flash and the storage partition (old offset/size) into
#    ./ota-migration-<timestamp>/
# 2. writes the bootloader (with rollback support), the new partition table, the initial otadata
#    and the app into ota_0
# 3. if nvs moved or grew: writes the old NVS bytes (from the full backup, padded with 0xFF to the
#    new size) at the nvs offset of the new table; otherwise NVS is not written
# 4. writes the storage dump back at the storage offset of the new table
# Offsets come from the two CSVs; every esptool command is printed and each write asks for
# confirmation. Do not use `idf.py flash` for this: it would also write a fresh
# storage.bin over /fatfs.
set -euo pipefail

usage() { echo "usage: $0 -p PORT [-b BAUD] [-d BUILD_DIR]" >&2; exit 2; }

REPO="$(cd "$(dirname "$0")/.." && pwd)"
APP_DIR="$REPO/application/edge_agent"
OLD_CSV="$APP_DIR/partitions_8MB.csv"
NEW_CSV="$APP_DIR/partitions_8MB_ota.csv"
BUILD="$APP_DIR/build"
PORT=""
BAUD=460800
FLASH_SIZE=$((8 * 1024 * 1024))

while getopts "p:b:d:" opt; do
    case "$opt" in
        p) PORT="$OPTARG" ;;
        b) BAUD="$OPTARG" ;;
        d) BUILD="$(cd "$OPTARG" && pwd)" ;;
        *) usage ;;
    esac
done
[ -n "$PORT" ] || usage
[ -n "${IDF_PATH:-}" ] || { echo "run this from an ESP-IDF shell (IDF_PATH is not set)" >&2; exit 1; }

# "<offset> <size>" in decimal of partition $2 in CSV $1, as gen_esp32part lays it out.
part() {
    python3 - "$IDF_PATH/components/partition_table" "$1" "$2" <<'PY'
import sys
sys.path.insert(0, sys.argv[1])
import gen_esp32part as g
g.quiet = True
table = g.PartitionTable.from_csv(open(sys.argv[2]).read())
table.verify()
p = table.find_by_name(sys.argv[3])
if p is None:
    sys.exit(f"no partition '{sys.argv[3]}' in {sys.argv[2]}")
print(p.offset, p.size)
PY
}

# Offset of image $1 in the build's flasher_args.json (bootloader, partition-table, otadata, app).
flash_offset() {
    python3 - "$BUILD/flasher_args.json" "$1" <<'PY'
import json, sys
print(int(json.load(open(sys.argv[1]))[sys.argv[2]]["offset"], 16))
PY
}

hex() { printf '0x%x' "$1"; }

ESPTOOL=(python -m esptool --chip esp32s3 -p "$PORT" -b "$BAUD")

run() {
    echo "+ ${ESPTOOL[*]} $*"
    "${ESPTOOL[@]}" "$@"
}

confirm() {
    local answer
    read -r -p "$1 Type 'yes' to continue: " answer
    [ "$answer" = "yes" ] || { echo "aborted, nothing more was written" >&2; exit 1; }
}

read -r OLD_STORAGE_OFF OLD_STORAGE_SIZE < <(part "$OLD_CSV" storage)
read -r NEW_STORAGE_OFF NEW_STORAGE_SIZE < <(part "$NEW_CSV" storage)
read -r OLD_NVS_OFF OLD_NVS_SIZE < <(part "$OLD_CSV" nvs)
read -r NEW_NVS_OFF NEW_NVS_SIZE < <(part "$NEW_CSV" nvs)
read -r OTA0_OFF OTA0_SIZE < <(part "$NEW_CSV" ota_0)
read -r OTADATA_OFF _ < <(part "$NEW_CSV" otadata)

[ "$NEW_NVS_SIZE" -ge "$OLD_NVS_SIZE" ] ||
    { echo "nvs is smaller in the new table; settings would not fit" >&2; exit 1; }
NVS_MOVED=$([ "$OLD_NVS_OFF $OLD_NVS_SIZE" = "$NEW_NVS_OFF $NEW_NVS_SIZE" ] && echo 0 || echo 1)
[ "$OLD_STORAGE_SIZE" = "$NEW_STORAGE_SIZE" ] ||
    { echo "storage size differs between the tables; a raw copy is not possible" >&2; exit 1; }

BOOTLOADER="$BUILD/bootloader/bootloader.bin"
PART_TABLE="$BUILD/partition_table/partition-table.bin"
OTADATA="$BUILD/ota_data_initial.bin"
APP="$BUILD/edge_agent.bin"
for f in "$BOOTLOADER" "$PART_TABLE" "$OTADATA" "$APP" "$BUILD/flasher_args.json"; do
    [ -f "$f" ] || { echo "missing $f: build edge_agent for esp32_S3_DevKitC_1 first" >&2; exit 1; }
done
BOOT_OFF=$(flash_offset bootloader)
PT_OFF=$(flash_offset partition-table)
# The build must have been made with the new table.
[ "$(flash_offset app)" = "$OTA0_OFF" ] && [ "$(flash_offset otadata)" = "$OTADATA_OFF" ] ||
    { echo "$BUILD was not built with partitions_8MB_ota.csv" >&2; exit 1; }
[ "$(stat -c %s "$APP")" -le "$OTA0_SIZE" ] || { echo "the app does not fit ota_0" >&2; exit 1; }
[ $((PT_OFF + 0x1000)) -le "$NEW_NVS_OFF" ] || { echo "the partition table would overlap nvs" >&2; exit 1; }

BACKUP="$PWD/ota-migration-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$BACKUP"
cp "$OLD_CSV" "$NEW_CSV" "$BACKUP/"
echo "Backups go to $BACKUP"
echo "storage: old $(hex "$OLD_STORAGE_OFF") -> new $(hex "$NEW_STORAGE_OFF"), $(hex "$NEW_STORAGE_SIZE") bytes;" \
     "nvs: old $(hex "$OLD_NVS_OFF") +$(hex "$OLD_NVS_SIZE") -> new $(hex "$NEW_NVS_OFF") +$(hex "$NEW_NVS_SIZE")" \
     "($([ "$NVS_MOVED" = 1 ] && echo "copied" || echo "not written"))"

echo "== 1/4 Backup (read only)"
run read_flash 0 "$(hex "$FLASH_SIZE")" "$BACKUP/full_flash_8MB.bin"
run read_flash "$(hex "$OLD_STORAGE_OFF")" "$(hex "$OLD_STORAGE_SIZE")" "$BACKUP/storage.bin"
[ "$(stat -c %s "$BACKUP/full_flash_8MB.bin")" = "$FLASH_SIZE" ] &&
    [ "$(stat -c %s "$BACKUP/storage.bin")" = "$OLD_STORAGE_SIZE" ] ||
    { echo "a backup has the wrong size" >&2; exit 1; }
# The storage dump must be the same bytes as that range of the full dump.
cmp <(tail -c +"$((OLD_STORAGE_OFF + 1))" "$BACKUP/full_flash_8MB.bin" | head -c "$OLD_STORAGE_SIZE") "$BACKUP/storage.bin" ||
    { echo "the two reads differ; check the USB connection and retry" >&2; exit 1; }
# Old NVS bytes from the full dump, padded with 0xFF (erased flash) to the new size.
{ dd if="$BACKUP/full_flash_8MB.bin" iflag=skip_bytes,count_bytes skip="$OLD_NVS_OFF" count="$OLD_NVS_SIZE" status=none
  head -c "$((NEW_NVS_SIZE - OLD_NVS_SIZE))" /dev/zero | tr '\0' '\377'; } > "$BACKUP/nvs.bin"
[ "$(stat -c %s "$BACKUP/nvs.bin")" = "$NEW_NVS_SIZE" ] || { echo "nvs.bin has the wrong size" >&2; exit 1; }
(cd "$BACKUP" && sha256sum full_flash_8MB.bin storage.bin nvs.bin > SHA256SUMS)

echo "== 2/4 Bootloader, partition table, otadata, app"
WRITE_ARGS=(write_flash "$(hex "$BOOT_OFF")" "$BOOTLOADER" "$(hex "$PT_OFF")" "$PART_TABLE"
            "$(hex "$OTADATA_OFF")" "$OTADATA" "$(hex "$OTA0_OFF")" "$APP")
echo "  ${ESPTOOL[*]} ${WRITE_ARGS[*]}"
confirm "This replaces the bootloader, partition table and app."
run "${WRITE_ARGS[@]}"

echo "== 3/4 NVS at its new offset"
if [ "$NVS_MOVED" = 1 ]; then
    NVS_ARGS=(write_flash "$(hex "$NEW_NVS_OFF")" "$BACKUP/nvs.bin")
    echo "  ${ESPTOOL[*]} ${NVS_ARGS[*]}"
    confirm "This writes the old NVS (settings) at the new nvs offset."
    run "${NVS_ARGS[@]}"
else
    echo "nvs is unchanged, not written"
fi

echo "== 4/4 Storage back at its new offset"
STORAGE_ARGS=(write_flash "$(hex "$NEW_STORAGE_OFF")" "$BACKUP/storage.bin")
echo "  ${ESPTOOL[*]} ${STORAGE_ARGS[*]}"
confirm "This writes the storage dump back."
run "${STORAGE_ARGS[@]}"

echo "Done. Reset the board and check /fw in Telegram. To undo everything:"
echo "  ${ESPTOOL[*]} write_flash 0 $BACKUP/full_flash_8MB.bin"
