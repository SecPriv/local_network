FILENAME_PREFIX=$(TZ=UTC date +%Y%m%d_%H%M%S)
OUT_FOLDER="out"
OUT_FILE="${OUT_FOLDER}/${FILENAME_PREFIX}_traffic.pcapng"

[ -z "$1" ] && echo "Usage: $0 <network-interface-name> (details see README.md)" && exit 1

echo "Starting tshark with network interface $1"
echo "Settting output file to $OUT_FILE"
tshark -i $1 -w $OUT_FILE
