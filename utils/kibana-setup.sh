#!/bin/bash
set -e

# Configuration
#KIBANA_URL="http://kibana:5601"
#KIBANA_USER="elastic"
#KIBANA_PASSWORD="${KIBANA_PASSWORD}"
#DATA_VIEW_TITLE="ogs-nginx-default"
#DATA_VIEW_NAME="Nginx Logs"
#TIME_FIELD="@timestamp"

CONFIG_FILE="/data-views.json"
CA_CERT="/certs/ca/ca.crt"
KIBANA_URL="https://kibana:5601"

# Validate required environment variables
if [ -z "${ELASTIC_PASSWORD}" ]; then
  echo "ERROR: ELASTIC_PASSWORD environment variable is not set"
  exit 1
fi

# Wait for Kibana to be fully ready
echo "Waiting for Kibana API to be ready..."
until curl -s -u "elastic:${ELASTIC_PASSWORD}" \
  --cacert "${CA_CERT}" \
  "${KIBANA_URL}/api/status" 2>/dev/null | grep -q '"level":"available"'; do
  echo "Kibana not fully ready yet, waiting..."
  sleep 5
done
echo "Kibana API is ready!"




echo ""
echo "============================================"
echo "Creating Data Views"
echo "============================================"



# Get total number of data views
TOTAL=$(jq '.data_views | length' "$CONFIG_FILE")
echo "Found $TOTAL data view(s) to create"
echo ""

#DEFAULT_DATAVIEW_ID=""

# Loop through each data view
i=0
while [ $i -lt $TOTAL ]; do
  # Extract data view properties
  TITLE=$(jq -r ".data_views[$i].title" "$CONFIG_FILE")
  NAME=$(jq -r ".data_views[$i].name" "$CONFIG_FILE")
  TIME_FIELD=$(jq -r ".data_views[$i].timeFieldName" "$CONFIG_FILE")
  #IS_DEFAULT=$(jq -r ".data_views[$i].default // false" "$CONFIG_FILE")

  echo "[$((i+1))/$TOTAL] Creating data view: $NAME"
  echo "       Index pattern: $TITLE"
  echo "       Time field: $TIME_FIELD"

  # Create the data view
  RESPONSE=$(curl -s -w "\n%{http_code}" -X POST \
    -u "elastic:${ELASTIC_PASSWORD}" \
    --cacert "${CA_CERT}" \
    -H "Content-Type: application/json" \
    -H "kbn-xsrf: true" \
    "${KIBANA_URL}/api/data_views/data_view" \
    -d "{
      \"data_view\": {
        \"title\": \"$TITLE\",
        \"name\": \"$NAME\",
        \"timeFieldName\": \"$TIME_FIELD\"
      }
    }")

  HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
  RESPONSE_BODY=$(echo "$RESPONSE" | sed '$d')

  if [ "$HTTP_CODE" = "200" ]; then
    echo "       Status: Created successfully"
    #DATAVIEW_ID=$(echo "$RESPONSE_BODY" | jq -r '.data_view.id')
  elif echo "$RESPONSE_BODY" | grep -q "Duplicate"; then
    echo "       Status: Already exists (skipped)"
    # Try to get existing data view ID for default setting
    #DATAVIEW_ID=$(curl -s -u "elastic:${ELASTIC_PASSWORD}" \
    #  -H "kbn-xsrf: true" \
    #  "http://kibana:5601/api/data_views" | jq -r ".data_view[] | select(.title==\"$TITLE\") | .id" 2>/dev/null || echo "")
  else
    echo "       Status: Failed (HTTP $HTTP_CODE)"
    echo "       Response: $RESPONSE_BODY"
    #DATAVIEW_ID=""
  fi

  # Track default data view
  #if [ "$IS_DEFAULT" = "true" ] && [ -n "$DATAVIEW_ID" ]; then
  #  DEFAULT_DATAVIEW_ID="$DATAVIEW_ID"
  #  echo "       Marked as default"
  #fi

  echo ""
  i=$((i + 1))
done

# Set default data view if specified
#if [ -n "$DEFAULT_DATAVIEW_ID" ]; then
#  echo "Setting default data view (ID: $DEFAULT_DATAVIEW_ID)..."
#  curl -s -X POST \
#    -u "elastic:${ELASTIC_PASSWORD}" \
#    -H "Content-Type: application/json" \
#    -H "kbn-xsrf: true" \
#    "http://kibana:5601/api/data_views/default" \
#    -d "{\"dataViewId\": \"$DEFAULT_DATAVIEW_ID\"}" > /dev/null
#  echo "Default data view configured!"
#  echo ""
#fi




echo "=========================================="
echo "Kibana setup completed successfully!"
echo "=========================================="
