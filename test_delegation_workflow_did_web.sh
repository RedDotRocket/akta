#!/bin/bash

set -e # Exit immediately if a command exits with a non-zero status.
# set -x # Debug mode: print each command before executing (optional)

# --- Configuration ---
SERVER_URL="http://localhost:8000"
VC_STORE_API_URL="${SERVER_URL}/api/v1/vc-store"
MAP_GENERATE_API_URL="${SERVER_URL}/api/v1/agent/map/generate"

# --- DID:WEB DOMAINS ---
# These domains will be used to construct did:web identifiers.
# For this script to work end-to-end, especially for API calls where the server
# needs to resolve these DIDs, you MUST ensure that:
# 1. These domain names resolve to a web server (e.g., via /etc/hosts for local testing).
# 2. The web server hosts the corresponding DID documents at the correct .well-known paths.
# Example for IA_DOMAIN:
#   - DID: did:web:issuer-alpha.akta.test
#   - DID Document URL: https://issuer-alpha.akta.test/.well-known/did.json
#   (or http:// if your server setup and client resolution logic supports it for testing)
#
# You might need to run a simple local HTTP server (e.g., 'python -m http.server')
# in a directory where these '.well-known/did.json' structures are placed,
# and map these domains to 127.0.0.1 in your /etc/hosts file.
IA_DOMAIN="issuer-alpha.akta.test"
AB_DOMAIN="agent-bob.akta.test"
AC_DOMAIN="agent-charlie.akta.test"

# File names for did:web
IA_KEY_FILE="issuer_alpha_web.key" # Contains keys + did:web info
IA_DID_DOC_FILE="issuer_alpha_did.json"

AB_KEY_FILE="agent_bob_web.key"
AB_DID_DOC_FILE="agent_bob_did.json"

AC_KEY_FILE="agent_charlie_web.key"
AC_DID_DOC_FILE="agent_charlie_did.json"

AB_SKILL_SUBJECT_FILE="agent_bob_skills_web.json"
AB_UNSIGNED_VC_FILE="unsigned_bob_vc_web.json"
AB_SIGNED_VC_FILE="signed_bob_vc_web.json" # This will be JSON containing the LDP proof

AC_DELEGATED_SUBJECT_FILE="agent_charlie_delegated_skills_web.json"
AC_UNSIGNED_VC_FILE="unsigned_charlie_delegated_vc_web.json"
AC_SIGNED_VC_FILE="signed_charlie_delegated_vc_web.json" # This will be JSON containing the LDP proof

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo_green() { echo -e "${GREEN}$1${NC}"; }
echo_yellow() { echo -e "${YELLOW}$1${NC}"; }
echo_red() { echo -e "${RED}$1${NC}"; }

# --- Helper function for Base64URL encoding ---
# Usage: base64url_encoded_string=$(base64url_encode "string_to_encode")
base64url_encode() {
    local input_string="$1"
    local encoded_string
    if [[ "$(uname)" == "Darwin" ]]; then
        # macOS: -b0 ensures no line breaks.
        encoded_string=$(echo -n "$input_string" | base64 -b0)
    else
        # Linux: -w0 ensures no line breaks.
        encoded_string=$(echo -n "$input_string" | base64 -w0)
    fi
    # URL-safe characters and remove padding
    echo "$encoded_string" | tr '+/' '-_' | tr -d '='
}


# --- Helper Function to Generate Keys and Extract DIDs (DID:WEB VERSION) ---
# Usage: generate_did_web_keys_if_needed <ENTITY_NAME_VAR> <DOMAIN_VAR> <KEY_FILE_VAR> <DID_DOC_FILE_VAR> <DID_VAR> <VERIFICATION_METHOD_VAR>
generate_did_web_keys_if_needed() {
    local entity_name_var=$1
    local domain_var=$2 # New: variable name holding the domain
    local key_file_var=$3
    local did_doc_file_var=$4 # New: variable name for DID doc output
    local did_var=$5
    local vm_var=$6

    if [ ! -f "${!key_file_var}" ] || [ ! -f "${!did_doc_file_var}" ]; then
        echo_yellow "Generating did:web keys and document for ${!entity_name_var} (${!domain_var})..."
        akta did create-did-web \
            --domain "${!domain_var}" \
            --output-keys "${!key_file_var}" \
            --output-did-document "${!did_doc_file_var}"
        echo_green "did:web keys and document created for ${!entity_name_var}."
        echo_yellow "IMPORTANT: Ensure ${!did_doc_file_var} is hosted correctly for ${!domain_var}"
    else
        echo_green "did:web keys and document for ${!entity_name_var} (${!key_file_var}, ${!did_doc_file_var}) already exist."
    fi
    
    # Export DID and Verification Method
    # For did:web, the verificationMethod is typically the full key ID from the DID document.
    # The --output-keys file from 'akta did create-did-web' should contain this.
    eval export "$did_var=$(jq -r '.did' "${!key_file_var}")"
    eval export "$vm_var=$(jq -r '.verificationMethod' "${!key_file_var}")" # This field is now in the keys file

    echo_green "${!entity_name_var} DID: ${!did_var}"
    echo_green "${!entity_name_var} Verification Method: ${!vm_var}"
    echo ""
}

# --- MAIN WORKFLOW ---

echo_yellow "===== Akta Delegated VC Workflow Test Script (DID:WEB VERSION) ====="
echo_red "IMPORTANT: This script uses did:web. For full end-to-end testing (Phases 3 & 4 API calls),"
echo_red "you MUST ensure the generated DID documents are resolvable by the Akta server."
echo_red "This typically means:"
echo_red "  1. Mapping domains ($IA_DOMAIN, $AB_DOMAIN, $AC_DOMAIN) to your local server IP (e.g., 127.0.0.1) in /etc/hosts."
echo_red "  2. Running a local HTTP server (e.g., 'python -m http.server 80' or 'python3 -m http.server 80' in a separate terminal)"
echo_red "     that serves the DID documents from the correct paths (e.g., ./issuer-alpha.akta.test/.well-known/did.json)."
echo_red "  The 'akta did create-did-web' command will tell you the expected URL. You'll need to create the"
echo_red "  directory structure (e.g., mkdir -p ${IA_DOMAIN}/.well-known && cp ${IA_DID_DOC_FILE} ${IA_DOMAIN}/.well-known/did.json) and serve from the parent directory."
echo_red "Without this setup, Phase 3 and 4 API calls WILL LIKELY FAIL during DID resolution."
echo_yellow "Ensure the Akta server is running on $SERVER_URL"

# Optional: Clean up old files at the start
# echo_yellow "Cleaning up previous test files..."
# rm -f "$IA_KEY_FILE" "$IA_DID_DOC_FILE" "$AB_KEY_FILE" "$AB_DID_DOC_FILE" "$AC_KEY_FILE" "$AC_DID_DOC_FILE" \
#       "$AB_SKILL_SUBJECT_FILE" "$AB_UNSIGNED_VC_FILE" "$AB_SIGNED_VC_FILE" \
#       "$AC_DELEGATED_SUBJECT_FILE" "$AC_UNSIGNED_VC_FILE" "$AC_SIGNED_VC_FILE"
# This cleanup will also need to remove non-delegable test files later
echo ""
sleep 2

# --- Phase 1: IssuerAlpha (IA) grants skills to AgentBob (AB) ---
echo_yellow "--- Phase 1: IssuerAlpha (IA) grants skills to AgentBob (AB) ---"

ENTITY_IA="IssuerAlpha"; generate_did_web_keys_if_needed ENTITY_IA IA_DOMAIN IA_KEY_FILE IA_DID_DOC_FILE IA_DID IA_VM
ENTITY_AB="AgentBob";    generate_did_web_keys_if_needed ENTITY_AB AB_DOMAIN AB_KEY_FILE AB_DID_DOC_FILE AB_DID AB_VM

echo_yellow "1.3: Preparing credentialSubject JSON for AgentBob's Skills (${AB_SKILL_SUBJECT_FILE})..."
cat << EOF > "$AB_SKILL_SUBJECT_FILE"
{
  "id": "$AB_DID",
  "skills": [
    {"scope": "map:generate", "granted": true}
  ],
  "conditions": {
    "canDelegate": true,
    "validUntil": "2025-12-31T23:59:59Z"
  }
}
EOF
echo_green "${AB_SKILL_SUBJECT_FILE} created."
echo ""

echo_yellow "1.4: Creating Unsigned VC for AgentBob (${AB_UNSIGNED_VC_FILE})..."
akta vc create \
    --issuer-did "$IA_DID" \
    --subject-did "$AB_DID" \
    --credential-subject "$AB_SKILL_SUBJECT_FILE" \
    --expiration-days 30 \
    --output "$AB_UNSIGNED_VC_FILE"
echo_green "${AB_UNSIGNED_VC_FILE} created."
echo ""

echo_yellow "1.5: IssuerAlpha signing the VC for AgentBob (${AB_SIGNED_VC_FILE})..."
akta vc sign \
    --vc-file "$AB_UNSIGNED_VC_FILE" \
    --issuer-key-file "$IA_KEY_FILE" \
    --verification-method "$IA_VM" \
    --output "$AB_SIGNED_VC_FILE"
echo_green "${AB_SIGNED_VC_FILE} created (contains LDP proof)."
echo ""

echo_yellow "1.6: Publishing AgentBob's VC to the VC Store..."
publish_output=$(akta vc-store publish --vc-file "$AB_SIGNED_VC_FILE" --store-url "$VC_STORE_API_URL")
echo "$publish_output" # Show the full output for debugging

JSON_BODY_EXTRACTED=$(echo "$publish_output" | awk '/Response Body: {/,/}/ {gsub("Response Body: ", ""); print}')
BOB_VC_ID_FROM_STORE=$(echo "$JSON_BODY_EXTRACTED" | jq -r '.vc_id // empty')

if [ -z "$BOB_VC_ID_FROM_STORE" ] || [ "$BOB_VC_ID_FROM_STORE" == "null" ] || [ "$BOB_VC_ID_FROM_STORE" == "empty" ]; then 
    echo_red "ERROR: Could not extract valid Bob's VC ID from store publish response."
    echo_red "Publish output was:"
    echo "$publish_output"
    echo_red "JSON body extracted for jq:"
    echo "$JSON_BODY_EXTRACTED"
    echo_red "ID Extracted by jq: $BOB_VC_ID_FROM_STORE"
    exit 1
fi
echo_green "AgentBob's VC published. VC ID from Store: $BOB_VC_ID_FROM_STORE"
echo ""


# --- Phase 2: AgentBob (AB) delegates skills to AgentCharlie (AC) ---
echo_yellow "--- Phase 2: AgentBob (AB) delegates skills to AgentCharlie (AC) ---"

ENTITY_AC="AgentCharlie"; generate_did_web_keys_if_needed ENTITY_AC AC_DOMAIN AC_KEY_FILE AC_DID_DOC_FILE AC_DID AC_VM

echo_yellow "2.2: Preparing credentialSubject JSON for AgentCharlie's Delegated Skills (${AC_DELEGATED_SUBJECT_FILE})..."
cat << EOF > "$AC_DELEGATED_SUBJECT_FILE"
{
  "id": "$AC_DID",
  "skills": [
    {"scope": "map:generate", "granted": true}
  ],
  "delegationDetails": {
    "parentVC": "$BOB_VC_ID_FROM_STORE",
    "delegatedBy": "$AB_DID",
    "validUntil": "2025-12-30T23:59:59Z"
  }
}
EOF
echo_green "${AC_DELEGATED_SUBJECT_FILE} created."
echo ""

echo_yellow "2.3: Creating Unsigned Delegated VC for AgentCharlie (${AC_UNSIGNED_VC_FILE})..."
echo_yellow "(Issuer is AgentBob: $AB_DID, Subject is AgentCharlie: $AC_DID)"
akta vc create \
    --issuer-did "$AB_DID" \
    --subject-did "$AC_DID" \
    --credential-subject "$AC_DELEGATED_SUBJECT_FILE" \
    --type VerifiableCredential --type SkillDelegation \
    --output "$AC_UNSIGNED_VC_FILE"
echo_green "${AC_UNSIGNED_VC_FILE} created."

ISSUER_IN_UNSIGNED_AC_VC=$(jq -r '.issuer' "$AC_UNSIGNED_VC_FILE")
if [ "$ISSUER_IN_UNSIGNED_AC_VC" != "$AB_DID" ]; then
    echo_red "ERROR: Issuer in ${AC_UNSIGNED_VC_FILE} is ${ISSUER_IN_UNSIGNED_AC_VC}, expected ${AB_DID}!"
    exit 1
fi
echo_green "Verified: Issuer in unsigned Charlie VC is AgentBob."
echo ""


echo_yellow "2.4: AgentBob signing the Delegated VC for AgentCharlie (${AC_SIGNED_VC_FILE})..."
akta vc sign \
    --vc-file "$AC_UNSIGNED_VC_FILE" \
    --issuer-key-file "$AB_KEY_FILE" \
    --verification-method "$AB_VM" \
    --output "$AC_SIGNED_VC_FILE"
echo_green "${AC_SIGNED_VC_FILE} created (contains LDP proof)."
echo ""


# --- Phase 3: Test API access with AgentCharlie's Delegated VC ---
echo_yellow "--- Phase 3: Test API access with AgentCharlie's Delegated VC ---"

echo_yellow "3.1: Preparing Bearer Token from AgentCharlie's signed VC (${AC_SIGNED_VC_FILE})..."
SIGNED_VC_JSON_CHARLIE_DELEGATED=$(cat "$AC_SIGNED_VC_FILE" | jq -c '.') # Compact JSON
if [ -z "$SIGNED_VC_JSON_CHARLIE_DELEGATED" ]; then
    echo_red "ERROR: Could not read/compact JSON from ${AC_SIGNED_VC_FILE}"
    exit 1
fi
BEARER_TOKEN_CHARLIE_DELEGATED=$(base64url_encode "$SIGNED_VC_JSON_CHARLIE_DELEGATED")
if [ -z "$BEARER_TOKEN_CHARLIE_DELEGATED" ]; then
    echo_red "ERROR: Could not create Bearer Token from ${AC_SIGNED_VC_FILE}"
    exit 1
fi
echo_green "Bearer Token prepared."
# echo "Bearer Token: $BEARER_TOKEN_CHARLIE_DELEGATED" # Uncomment to see token

echo_yellow "3.2: Calling /map/generate API with AgentCharlie's Delegated VC..."
API_RESPONSE=$(curl -s -w "\n%{http_code}" -X POST \
     -H "Authorization: Bearer $BEARER_TOKEN_CHARLIE_DELEGATED" \
     -H "Content-Type: application/json" \
     -d '{"region": "script_europe_did_web", "style": "script_satellite_did_web"}' \
     "$MAP_GENERATE_API_URL")

HTTP_CODE=$(echo "$API_RESPONSE" | tail -n1)
API_BODY=$(echo "$API_RESPONSE" | sed '$d')

echo "Response Body: $API_BODY"
echo "HTTP Status Code: $HTTP_CODE"

if [ "$HTTP_CODE" -eq 200 ]; then
    echo_green "SUCCESS: API call with AgentCharlie's delegated VC succeeded (HTTP $HTTP_CODE)!"
else
    echo_red "FAILURE: API call with AgentCharlie's delegated VC failed (HTTP $HTTP_CODE)."
    echo_red "REMINDER: For did:web, ensure DID documents are resolvable by the server via HTTP."
    exit 1
fi
echo ""

echo_green "===== All tests for successful delegation passed! ====="
echo ""
echo_yellow "To test the 'canDelegate: false' scenario, you would:"
echo_yellow "1. Modify ${AB_SKILL_SUBJECT_FILE} to set 'canDelegate': false (or remove 'conditions')."
echo_yellow "2. Re-run Phase 1 (steps 1.3-1.6) to create and publish a new VC for Bob."
echo_yellow "3. Re-run Phase 2 (steps 2.2-2.4) to create a new delegated VC for Charlie pointing to Bob's new non-delegable VC."
echo_yellow "4. Re-run Phase 3 (steps 3.1-3.2) and expect an HTTP 403 Forbidden error."
echo ""

# --- Phase 4: Test 'canDelegate: false' scenario ---
echo_yellow "===== Phase 4: Test 'canDelegate: false' scenario ====="
echo ""

# Define new filenames for this phase to avoid conflicts
AB_SKILL_SUBJECT_NO_DELEGATE_FILE="agent_bob_skills_no_delegate_web.json"
AB_UNSIGNED_VC_NO_DELEGATE_FILE="unsigned_bob_vc_no_delegate_web.json"
AB_SIGNED_VC_NO_DELEGATE_FILE="signed_bob_vc_no_delegate_web.json"
# We will also need new DID Doc for Bob in this scenario, as it's a new VC from IssuerAlpha
AB_KEY_NO_DELEGATE_FILE="agent_bob_web_no_delegate.key" # Key file for Bob's non-delegable VC identity
AB_DID_DOC_NO_DELEGATE_FILE="agent_bob_did_no_delegate.json" # DID Doc for Bob's non-delegable VC identity


AC_DELEGATED_SUBJECT_FROM_NO_DELEGATE_FILE="agent_charlie_delegated_skills_from_no_delegate_web.json"
AC_UNSIGNED_VC_FROM_NO_DELEGATE_FILE="unsigned_charlie_delegated_vc_from_no_delegate_web.json"
AC_SIGNED_VC_FROM_NO_DELEGATE_FILE="signed_charlie_delegated_vc_from_no_delegate_web.json"


echo_yellow "4.1: Preparing credentialSubject JSON for AgentBob's NON-DELEGABLE Skills (${AB_SKILL_SUBJECT_NO_DELEGATE_FILE})..."
# For this scenario, Bob still needs a DID. We will re-use AB_DID created earlier for simplicity of subject ID.
# However, the VC from IA to AB will be new, and its reference (BOB_VC_ID_NO_DELEGATE_FROM_STORE) will be new.
# When Bob issues a delegated VC to Charlie (attempted), Bob's DID (AB_DID) and key ($AB_KEY_FILE) are used.
# The change is in the *content* of the VC IA gives to Bob regarding 'canDelegate'.
# No new DID for Bob is strictly needed for this test, we use the same AB_DID and AB_VM.
# The critical part is the parentVC ID in Charlie's delegated credential subject.

cat << EOF > "$AB_SKILL_SUBJECT_NO_DELEGATE_FILE"
{
  "id": "$AB_DID",
  "skills": [
    {"scope": "map:generate", "granted": true}
  ],
  "conditions": {
    "canDelegate": false,
    "validUntil": "2025-12-31T23:59:59Z"
  }
}
EOF
echo_green "${AB_SKILL_SUBJECT_NO_DELEGATE_FILE} created."
echo ""

echo_yellow "4.2: Creating Unsigned NON-DELEGABLE VC for AgentBob (${AB_UNSIGNED_VC_NO_DELEGATE_FILE})..."
# IssuerAlpha (IA_DID) issues this to AgentBob (AB_DID)
akta vc create \
    --issuer-did "$IA_DID" \
    --subject-did "$AB_DID" \
    --credential-subject "$AB_SKILL_SUBJECT_NO_DELEGATE_FILE" \
    --expiration-days 30 \
    --output "$AB_UNSIGNED_VC_NO_DELEGATE_FILE"
echo_green "${AB_UNSIGNED_VC_NO_DELEGATE_FILE} created."
echo ""

echo_yellow "4.3: IssuerAlpha signing the NON-DELEGABLE VC for AgentBob (${AB_SIGNED_VC_NO_DELEGATE_FILE})..."
akta vc sign \
    --vc-file "$AB_UNSIGNED_VC_NO_DELEGATE_FILE" \
    --issuer-key-file "$IA_KEY_FILE" \
    --verification-method "$IA_VM" \
    --output "$AB_SIGNED_VC_NO_DELEGATE_FILE"
echo_green "${AB_SIGNED_VC_NO_DELEGATE_FILE} created (contains LDP proof)."
echo ""

echo_yellow "4.4: Publishing AgentBob's NON-DELEGABLE VC to the VC Store..."
publish_output_no_delegate=$(akta vc-store publish --vc-file "$AB_SIGNED_VC_NO_DELEGATE_FILE" --store-url "$VC_STORE_API_URL")
echo "$publish_output_no_delegate"

JSON_BODY_EXTRACTED_NO_DELEGATE=$(echo "$publish_output_no_delegate" | awk '/Response Body: {/,/}/ {gsub("Response Body: ", ""); print}')
BOB_VC_ID_NO_DELEGATE_FROM_STORE=$(echo "$JSON_BODY_EXTRACTED_NO_DELEGATE" | jq -r '.vc_id // empty')

if [ -z "$BOB_VC_ID_NO_DELEGATE_FROM_STORE" ] || [ "$BOB_VC_ID_NO_DELEGATE_FROM_STORE" == "null" ] || [ "$BOB_VC_ID_NO_DELEGATE_FROM_STORE" == "empty" ]; then
    echo_red "ERROR: Could not extract Bob's NON-DELEGABLE VC ID from store publish response."
    echo_red "Publish output was:"
    echo "$publish_output_no_delegate"
    exit 1
fi
echo_green "AgentBob's NON-DELEGABLE VC published. VC ID from Store: $BOB_VC_ID_NO_DELEGATE_FROM_STORE"
echo ""

echo_yellow "4.5: Preparing credentialSubject for AgentCharlie, attempting to delegate from Bob's NON-DELEGABLE VC (${AC_DELEGATED_SUBJECT_FROM_NO_DELEGATE_FILE})..."
# AgentCharlie's DID (AC_DID) is the subject.
cat << EOF > "$AC_DELEGATED_SUBJECT_FROM_NO_DELEGATE_FILE"
{
  "id": "$AC_DID",
  "skills": [
    {"scope": "map:generate", "granted": true}
  ],
  "delegationDetails": {
    "parentVC": "$BOB_VC_ID_NO_DELEGATE_FROM_STORE",
    "delegatedBy": "$AB_DID",
    "validUntil": "2025-12-30T23:59:59Z"
  }
}
EOF
echo_green "${AC_DELEGATED_SUBJECT_FROM_NO_DELEGATE_FILE} created."
echo ""

echo_yellow "4.6: Creating Unsigned (Attempted) Delegated VC for AgentCharlie (${AC_UNSIGNED_VC_FROM_NO_DELEGATE_FILE})..."
# AgentBob (AB_DID) is ISSUING this to AgentCharlie (AC_DID)
akta vc create \
    --issuer-did "$AB_DID" \
    --subject-did "$AC_DID" \
    --credential-subject "$AC_DELEGATED_SUBJECT_FROM_NO_DELEGATE_FILE" \
    --type VerifiableCredential --type SkillDelegation \
    --output "$AC_UNSIGNED_VC_FROM_NO_DELEGATE_FILE"
echo_green "${AC_UNSIGNED_VC_FROM_NO_DELEGATE_FILE} created."
echo ""

echo_yellow "4.7: AgentBob signing the (Attempted) Delegated VC for AgentCharlie (${AC_SIGNED_VC_FROM_NO_DELEGATE_FILE})..."
# AgentBob uses his key (AB_KEY_FILE) and VM (AB_VM)
akta vc sign \
    --vc-file "$AC_UNSIGNED_VC_FROM_NO_DELEGATE_FILE" \
    --issuer-key-file "$AB_KEY_FILE" \
    --verification-method "$AB_VM" \
    --output "$AC_SIGNED_VC_FROM_NO_DELEGATE_FILE"
echo_green "${AC_SIGNED_VC_FROM_NO_DELEGATE_FILE} created (contains LDP proof)."
echo ""

echo_yellow "4.8: Test API access with AgentCharlie's (INVALID) Delegated VC..."
SIGNED_VC_JSON_CHARLIE_FROM_NO_DELEGATE=$(cat "$AC_SIGNED_VC_FROM_NO_DELEGATE_FILE" | jq -c '.') # Compact JSON
if [ -z "$SIGNED_VC_JSON_CHARLIE_FROM_NO_DELEGATE" ]; then
    echo_red "ERROR: Could not read/compact JSON from ${AC_SIGNED_VC_FROM_NO_DELEGATE_FILE}"
    exit 1
fi
BEARER_TOKEN_CHARLIE_FROM_NO_DELEGATE=$(base64url_encode "$SIGNED_VC_JSON_CHARLIE_FROM_NO_DELEGATE")
if [ -z "$BEARER_TOKEN_CHARLIE_FROM_NO_DELEGATE" ]; then
    echo_red "ERROR: Could not create Bearer Token from ${AC_SIGNED_VC_FROM_NO_DELEGATE_FILE}"
    exit 1
fi
echo_green "Bearer Token prepared for invalid delegation test."

echo_yellow "Calling /map/generate API with AgentCharlie's (INVALID) Delegated VC (expecting 403)..."
API_RESPONSE_NO_DELEGATE=$(curl -s -w "\n%{http_code}" -X POST \
     -H "Authorization: Bearer $BEARER_TOKEN_CHARLIE_FROM_NO_DELEGATE" \
     -H "Content-Type: application/json" \
     -d '{"region": "script_europe_fail_did_web", "style": "script_satellite_fail_did_web"}' \
     "$MAP_GENERATE_API_URL")

HTTP_CODE_NO_DELEGATE=$(echo "$API_RESPONSE_NO_DELEGATE" | tail -n1)
API_BODY_NO_DELEGATE=$(echo "$API_RESPONSE_NO_DELEGATE" | sed '$d')

echo "Response Body (expect 403): $API_BODY_NO_DELEGATE"
echo "HTTP Status Code (expect 403): $HTTP_CODE_NO_DELEGATE"

if [ "$HTTP_CODE_NO_DELEGATE" -eq 403 ]; then
    echo_green "SUCCESS: API call with AgentCharlie's VC (delegated from non-delegable parent) correctly FAILED with HTTP 403 Forbidden!"
else
    echo_red "FAILURE: API call with AgentCharlie's VC (delegated from non-delegable parent) returned HTTP $HTTP_CODE_NO_DELEGATE, but expected 403 Forbidden."
    echo_red "REMINDER: For did:web, ensure DID documents are resolvable by the server via HTTP."
    exit 1
fi
echo ""

echo_green "===== All tests, including 'canDelegate: false' scenario, passed! ====="
echo ""
echo_yellow "To clean up ALL generated files, you can uncomment and run the cleanup block below or manually delete:"
echo_yellow "Key files: $IA_KEY_FILE, $AB_KEY_FILE, $AC_KEY_FILE"
echo_yellow "DID Documents: $IA_DID_DOC_FILE, $AB_DID_DOC_FILE, $AC_DID_DOC_FILE"
echo_yellow "Successful delegation files: $AB_SKILL_SUBJECT_FILE, $AB_UNSIGNED_VC_FILE, $AB_SIGNED_VC_FILE, $AC_DELEGATED_SUBJECT_FILE, $AC_UNSIGNED_VC_FILE, $AC_SIGNED_VC_FILE"
echo_yellow "Non-delegable test files: $AB_SKILL_SUBJECT_NO_DELEGATE_FILE, $AB_UNSIGNED_VC_NO_DELEGATE_FILE, $AB_SIGNED_VC_NO_DELEGATE_FILE, $AC_DELEGATED_SUBJECT_FROM_NO_DELEGATE_FILE, $AC_UNSIGNED_VC_FROM_NO_DELEGATE_FILE, $AC_SIGNED_VC_FROM_NO_DELEGATE_FILE"
# Consider also the AB_KEY_NO_DELEGATE_FILE and AB_DID_DOC_NO_DELEGATE_FILE if they were used differently, but current script reuses AB_DID.
echo_yellow "And the vc_store.db file if you want to reset the VC Store."
echo_yellow "And any directories created to serve DID documents (e.g., ${IA_DOMAIN}/.well-known/)."
echo ""

# Optional: Cleanup generated files
# echo_yellow "Cleaning up ALL generated files..."
# rm -f "$IA_KEY_FILE" "$IA_DID_DOC_FILE" "$AB_KEY_FILE" "$AB_DID_DOC_FILE" "$AC_KEY_FILE" "$AC_DID_DOC_FILE" \
#       "$AB_SKILL_SUBJECT_FILE" "$AB_UNSIGNED_VC_FILE" "$AB_SIGNED_VC_FILE" \
#       "$AC_DELEGATED_SUBJECT_FILE" "$AC_UNSIGNED_VC_FILE" "$AC_SIGNED_VC_FILE" \
#       "$AB_SKILL_SUBJECT_NO_DELEGATE_FILE" "$AB_UNSIGNED_VC_NO_DELEGATE_FILE" "$AB_SIGNED_VC_NO_DELEGATE_FILE" \
#       "$AC_DELEGATED_SUBJECT_FROM_NO_DELEGATE_FILE" "$AC_UNSIGNED_VC_FROM_NO_DELEGATE_FILE" "$AC_SIGNED_VC_FROM_NO_DELEGATE_FILE"
# echo_green "Cleanup complete."

exit 0 