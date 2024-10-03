FILENAME_PREFIX=$(TZ=UTC date +%Y%m%d_%H%M%S)
OUT_FOLDER="out"
OUT_FILE="${OUT_FOLDER}/${FILENAME_PREFIX}_appium.log"

echo "Starting appium"
echo "Settting log output file to $OUT_FILE"
appium --log $OUT_FILE --base-path /wd/hub --port $1
