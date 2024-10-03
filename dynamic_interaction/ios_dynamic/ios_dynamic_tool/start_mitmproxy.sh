FILENAME_PREFIX=$(TZ=UTC date +%Y%m%d_%H%M%S)
OUT_FOLDER="out"
OUT_FILE_LOG="${OUT_FOLDER}/${FILENAME_PREFIX}_mitmproxy.log"
OUT_FILE_KEYS="${OUT_FOLDER}/${FILENAME_PREFIX}_mitmproxy_ssl_keys.txt"

echo "Starting mitmproxy (mitmdump) on port $1"
echo "Settting output file to $OUT_FILE_LOG"
echo "Logging SSL Key-Exchanges to $OUT_FILE_KEYS"
echo "Hint: Afterwards, you could use the following command to browse and analyze the intercepted network traffic: mitmweb --rfile $OUT_FILE_LOG"
echo ""

SSLKEYLOGFILE=$OUT_FILE_KEYS mitmdump -w $OUT_FILE_LOG -p $1