#!/bin/bash
export OPENAI_API_KEY="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"
export CHATGPT_DIR="./test_files"
export INPUT_FILES=()
export CHATGPT_CODE=""

mapfile -t INPUT_FILES < <(find "${CHATGPT_DIR}" -name "*.js" -or -name "*.lua" -type f 2>/dev/null)

for FILE in "${INPUT_FILES[@]}" ; do
  #cat "$FILE"
  #printf -v CHATGPT_CODE '%q' $(cat "$FILE")
  #head -n -4 $CHATGPT_DIR/template.json > $CHATGPT_DIR/chat.json
  # CHATGPT_CODE=$(sed 's/[][`~!@#$%^&*()-_=+{}\|;:",<.>?'"'"']/\\&/g' "$FILE")
  CHATGPT_CODE=$(sed 's/"/\\\"/g' "$FILE" | tr -d '[:space:]')
  echo "$CHATGPT_CODE" #  >> $CHATGPT_DIR/chat.json
  #echo '	"
  #	}],
  #}' >> $CHATGPT_DIR/chat.json
  #sed -r "s/CHATGPT_CODE/?/g" $CHATGPT_DIR/template.json | cut -d "?" -f 2 >> $CHATGPT_DIR/chat.json
  sed -r "s/CHATGPT_CODE/$CHATGPT_CODE/g" $CHATGPT_DIR/template.json > $CHATGPT_DIR/chat.json
  #cat $CHATGPT_DIR/chat.json| tr -d '[:space:]' > $CHATGPT_DIR/chat.json
  echo "this is the file:"
  cat $CHATGPT_DIR/chat.json

  curl https://api.openai.com/v1/chat/completions -H "Content-Type: application/json" \
  	-H "Authorization: Bearer $OPENAI_API_KEY" \
  	-d @$CHATGPT_DIR/chat.json -v
  	  #curl -X POST https://api.openai.com/v1/files \
  	    	# -F purpose="fine-tune" \
  	#-F "file=@$CHATGPT_DIR/download.lua"
done