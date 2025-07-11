#!/bin/bash

set -e # Exit immediately if a command exits with a non-zero status.
# set -x # Debug mode: print each command before executing (optional)

# --- Configuration ---
BASE_URL="http://localhost:8050/api/v1"
MAP_GENERATE_API_URL="${BASE_URL}/map/generate"
AGENTCARD_URL="${BASE_URL}/.well-known/agent.json"

# File names
IA_KEY_FILE="issuer.key"
AB_KEY_FILE="bob.key"
AC_KEY_FILE="charlie.key"

AB_SKILL_SUBJECT_FILE="agent_bob_skills.json"
AB_UNSIGNED_VC_FILE="unsigned_bob_vc.json"
AB_SIGNED_VC_FILE="signed_bob_vc.json" # This will be JSON containing the LDP proof

AC_DELEGATED_SUBJECT_FILE="agent_charlie_delegated_skills.json"
AC_UNSIGNED_VC_FILE="unsigned_charlie_delegated_vc.json"
AC_SIGNED_VC_FILE="signed_charlie_delegated_vc.json" # This will be JSON containing the LDP proof

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo_green() { echo -e "${GREEN}$1${NC}"; }
echo_yellow() { echo -e "${YELLOW}$1${NC}"; }
echo_red() { echo -e "${RED}$1${NC}"; }
echo_new_line() { echo ""; }


# --- Helper Function to Generate Keys and Extract DIDs ---
# Usage: generate_keys_if_needed <ENTITY_NAME_VAR> <KEY_FILE_VAR> <DID_VAR> <VERIFICATION_METHOD_VAR>
generate_keys_if_needed() {
    local entity_name_var=$1
    local key_file_var=$2
    local did_var=$3
    local vm_var=$4

    if [ ! -f "${!key_file_var}" ]; then
        echo_yellow "Generating keys for ${!entity_name_var}..."
        akta keys create-key --output "${!key_file_var}"
    else
        echo_green "Keys for ${!entity_name_var} (${!key_file_var}) already exist."
    fi

    # Export DID and Verification Method (controller)
    # The commandsubst below will fail if jq is not installed or key file is malformed
    # Which is good due to set -e
    eval export "$did_var=$(jq -r '.did' "${!key_file_var}")"
    eval export "$vm_var=$(jq -r '.verificationMethod' "${!key_file_var}")"

    echo_green "${!entity_name_var} DID: ${!did_var}"
    echo_green "${!entity_name_var} Verification Method: ${!vm_var}"
    echo ""
}

# --- MAIN WORKFLOW ---

echo_yellow "===== Akta Delegated VC Workflow Test Script ====="
echo_yellow "Ensure the Akta server is running on $BASE_URL"
# Optional: Clean up old files at the start
echo_yellow "Cleaning up previous test files..."
rm -f "$IA_KEY_FILE" "$AB_KEY_FILE" "$AC_KEY_FILE" \
      "$AB_SKILL_SUBJECT_FILE" "$AB_UNSIGNED_VC_FILE" "$AB_SIGNED_VC_FILE" \
      "$AC_DELEGATED_SUBJECT_FILE" "$AC_UNSIGNED_VC_FILE" "$AC_SIGNED_VC_FILE"
echo_new_line
sleep 2

# --- Phase 1: Issuer (IA) grants skills to AgentBob (AB) ---
echo_yellow "--- Phase 1: Issuer (IA) grants skills to AgentBob (AB) ---"

ENTITY_IA="Issuer"; generate_keys_if_needed ENTITY_IA IA_KEY_FILE IA_DID IA_VM
ENTITY_AB="AgentBob";    generate_keys_if_needed ENTITY_AB AB_KEY_FILE AB_DID AB_VM


echo_yellow "1.3: Checking for AgentCard from A2A Agent Server at (${AGENTCARD_URL})..."
curl "${AGENTCARD_URL}"

echo_new_line

echo_yellow "1.4: Creating Unsigned VC for AgentBob (${AB_UNSIGNED_VC_FILE})..."
akta claim fetch-agentcard \
    --issuer-did "$IA_DID" \
    --subject-did "$AB_DID" \
    --url "${AGENTCARD_URL}" \
    --usage-limit 10 \
    --can-delegate \
    --output "$AB_UNSIGNED_VC_FILE"

echo_new_line

echo_yellow "1.5: Signing VC for AgentBob (${AB_SIGNED_VC_FILE})..."
akta claim sign \
    --vc-file "$AB_UNSIGNED_VC_FILE" \
    --issuer-key-file "$IA_KEY_FILE" \
    --verification-method "$IA_VM" \
    --output "$AB_SIGNED_VC_FILE"

echo_new_line

echo_yellow "1.6: Publishing AgentBob's VC to the VC Store (${BASE_URL})..."

push_output=$(akta registry push --vc-file "$AB_SIGNED_VC_FILE" --vdr-url "$BASE_URL")
echo "$push_output"

echo_new_line

echo_yellow "1.6: Pulling AgentBob's VC from the VC Store..."
pull_output=$(akta registry pull --vc-id "$(jq -r '.id' "$AB_SIGNED_VC_FILE")" --vdr-url "$BASE_URL" )
echo "$pull_output"

# echo_new_line

# echo_yellow "1.7: Obtain Token for AgentBob's VC..."

# token_output=$(akta token generate --vc-file "$AB_SIGNED_VC_FILE" --raw-token)

# echo_new_line

# # Extract vc_id using jq from the relevant part of the output
# # The awk command extracts the multi-line JSON block starting after "Response Body: "
BOB_VC_ID_FROM_STORE=$(echo "$pull_output" | jq -r '.id // empty')

# echo BOB_VC_ID_FROM_STORE
echo "BOB_VC_ID_FROM_STORE: $BOB_VC_ID_FROM_STORE"


# --- Phase 2: AgentBob (AB) delegates skills to AgentCharlie (AC) ---
echo_yellow "--- Phase 2: AgentBob (AB) delegates skills to AgentCharlie (AC) ---"

ENTITY_AC="AgentCharlie"; generate_keys_if_needed ENTITY_AC AC_KEY_FILE AC_DID AC_VM

echo_yellow "2.1: Preparing credentialSubject JSON for AgentCharlie's Delegated Skills (${AC_DELEGATED_SUBJECT_FILE})..."
cat << EOF > "$AC_DELEGATED_SUBJECT_FILE"
{
  "id": "$AC_DID",
  "skills": [
    {
      "scope": [
        "map:generate"
      ],
      "granted": true,
      "usageLimit": 10
    }
  ],
  "delegationDetails": {
    "parentVC": "$BOB_VC_ID_FROM_STORE",
    "delegatedBy": "$AB_DID",
    "validUntil": "2025-12-30T23:59:59Z"
  }
}
EOF
echo_green "${AC_DELEGATED_SUBJECT_FILE} created."
echo_new_line

echo_yellow "2.3: Creating Unsigned Delegated VC for AgentCharlie (${AC_UNSIGNED_VC_FILE})..."
echo_yellow "(Issuer is AgentBob: $AB_DID, Subject is AgentCharlie: $AC_DID)"
akta claim draft \
    --method key \
    --issuer-did "$AB_DID" \
    --subject-did "$AC_DID" \
    --credential-subject "$AC_DELEGATED_SUBJECT_FILE" \
    --type VerifiableCredential --type SkillDelegation \
    --output "$AC_UNSIGNED_VC_FILE"
echo_green "${AC_UNSIGNED_VC_FILE} created."

# # Sanity check: cat unsigned_charlie_delegated_vc.json | jq '.issuer' should be Bob's DID
ISSUER_IN_UNSIGNED_AC_VC=$(jq -r '.issuer' "$AC_UNSIGNED_VC_FILE")
if [ "$ISSUER_IN_UNSIGNED_AC_VC" != "$AB_DID" ]; then
    echo_red "ERROR: Issuer in ${AC_UNSIGNED_VC_FILE} is ${ISSUER_IN_UNSIGNED_AC_VC}, expected ${AB_DID}!"
    exit 1
fi
echo_green "Verified: Issuer in unsigned Charlie VC is AgentBob."
echo ""


echo_yellow "2.4: AgentBob signing the Delegated VC for AgentCharlie (${AC_SIGNED_VC_FILE})..."
akta claim sign \
    --vc-file "$AC_UNSIGNED_VC_FILE" \
    --issuer-key-file "$AB_KEY_FILE" \
    --verification-method "$AB_VM" \
    --output "$AC_SIGNED_VC_FILE"
echo_green "${AC_SIGNED_VC_FILE} created (contains LDP proof)."
echo ""


# --- Phase 3: Test API access with AgentCharlie's Delegated VC ---
echo_yellow "--- Phase 3: Test API access with AgentCharlie's Delegated VC ---"

echo_yellow "3.1: Preparing Bearer Token from AgentCharlie's signed VC (${AC_SIGNED_VC_FILE})..."
BEARER_TOKEN_CHARLIE_DELEGATED=$(akta token generate --vc-file "$AC_SIGNED_VC_FILE" --raw-token)

echo_yellow "3.2: Calling /map/generate API with AgentCharlie's Delegated VC..."
API_RESPONSE=$(curl -s -w "\n%{http_code}" -X POST \
     -H "Authorization: Bearer $BEARER_TOKEN_CHARLIE_DELEGATED" \
     -H "Content-Type: application/json" \
     -d '{"region": "script_europe", "style": "script_satellite"}' \
     "$MAP_GENERATE_API_URL")

HTTP_CODE=$(echo "$API_RESPONSE" | tail -n1)
API_BODY=$(echo "$API_RESPONSE" | sed '$d')

echo "Response Body: $API_BODY"
echo "HTTP Status Code: $HTTP_CODE"

if [ "$HTTP_CODE" -eq 200 ]; then
    echo_green "SUCCESS: API call with AgentCharlie's delegated VC succeeded (HTTP $HTTP_CODE)!"
else
    echo_red "FAILURE: API call with AgentCharlie's delegated VC failed (HTTP $HTTP_CODE)."
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

# # --- Phase 4: Test 'canDelegate: false' scenario ---
echo_yellow "===== Phase 4: Test 'canDelegate: false' scenario ====="
# echo ""

# # Define new filenames for this phase to avoid conflicts
AB_SKILL_SUBJECT_NO_DELEGATE_FILE="agent_bob_skills_no_delegate.json"
AB_UNSIGNED_VC_NO_DELEGATE_FILE="unsigned_bob_vc_no_delegate.json"
AB_SIGNED_VC_NO_DELEGATE_FILE="signed_bob_vc_no_delegate.json"

AC_DELEGATED_SUBJECT_FROM_NO_DELEGATE_FILE="agent_charlie_delegated_skills_from_no_delegate.json"
AC_UNSIGNED_VC_FROM_NO_DELEGATE_FILE="unsigned_charlie_delegated_vc_from_no_delegate.json"
AC_SIGNED_VC_FROM_NO_DELEGATE_FILE="signed_charlie_delegated_vc_from_no_delegate.json"


echo_yellow "4.1: Preparing credentialSubject JSON for AgentBob's NON-DELEGABLE Skills (${AB_SKILL_SUBJECT_NO_DELEGATE_FILE})..."
cat << EOF > "$AB_SKILL_SUBJECT_NO_DELEGATE_FILE"
{
  "id": "$AB_DID",
  "skills": [
    {"scope": ["map:generate"], "granted": true}
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
akta claim draft \
    --method key \
    --issuer-did "$IA_DID" \
    --subject-did "$AB_DID" \
    --credential-subject "$AB_SKILL_SUBJECT_NO_DELEGATE_FILE" \
    --type VerifiableCredential \
    --output "$AB_UNSIGNED_VC_NO_DELEGATE_FILE"
echo_green "${AB_UNSIGNED_VC_NO_DELEGATE_FILE} created."


echo_yellow "4.3: Issuer signing the NON-DELEGABLE VC for AgentBob (${AB_SIGNED_VC_NO_DELEGATE_FILE})..."
akta claim sign \
    --vc-file "$AB_UNSIGNED_VC_NO_DELEGATE_FILE" \
    --issuer-key-file "$IA_KEY_FILE" \
    --verification-method "$IA_VM" \
    --output "$AB_SIGNED_VC_NO_DELEGATE_FILE"
echo_green "${AB_SIGNED_VC_NO_DELEGATE_FILE} created (contains LDP proof)."
echo ""

echo_yellow "4.4: Publishing AgentBob's NON-DELEGABLE VC to the VC Store..."
BOB_VC_ID_NO_DELEGATE_FROM_STORE=$(akta registry push --vc-file "$AB_SIGNED_VC_NO_DELEGATE_FILE" --vdr-url "$BASE_URL" --urn-only)
echo "$push_output_no_delegate"
# BOB_VC_ID_NO_DELEGATE_FROM_STORE=$(echo "$push_output_no_delegate" | jq -r '.id')

if [ -z "$BOB_VC_ID_NO_DELEGATE_FROM_STORE" ]; then
    echo_red "ERROR: Could not extract Bob's NON-DELEGABLE VC ID from store publish response."
    echo_red "Publish output was:"
    echo "$BOB_VC_ID_NO_DELEGATE_FROM_STORE"
    exit 1
fi
echo_green "AgentBob's NON-DELEGABLE VC published. VC ID from Store: $BOB_VC_ID_NO_DELEGATE_FROM_STORE"
echo ""

echo_yellow "4.5: Preparing credentialSubject for AgentCharlie, attempting to delegate from Bob's NON-DELEGABLE VC (${AC_DELEGATED_SUBJECT_FROM_NO_DELEGATE_FILE})..."
cat << EOF > "$AC_DELEGATED_SUBJECT_FROM_NO_DELEGATE_FILE"
{
  "id": "$AC_DID",
  "skills": [
    {"scope": ["map:generate"], "granted": true}
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
akta claim draft \
    --method key \
    --issuer-did "$AB_DID" \
    --subject-did "$AC_DID" \
    --credential-subject "$AC_DELEGATED_SUBJECT_FROM_NO_DELEGATE_FILE" \
    --type VerifiableCredential --type SkillDelegation \
    --output "$AC_UNSIGNED_VC_FROM_NO_DELEGATE_FILE"
echo_green "${AC_UNSIGNED_VC_FROM_NO_DELEGATE_FILE} created."
echo ""

echo_yellow "4.7: AgentBob signing the (Attempted) Delegated VC for AgentCharlie (${AC_SIGNED_VC_FROM_NO_DELEGATE_FILE})..."
akta claim sign \
    --vc-file "$AC_UNSIGNED_VC_FROM_NO_DELEGATE_FILE" \
    --issuer-key-file "$AB_KEY_FILE" \
    --verification-method "$AB_VM" \
    --output "$AC_SIGNED_VC_FROM_NO_DELEGATE_FILE"
echo_green "${AC_SIGNED_VC_FROM_NO_DELEGATE_FILE} created (contains LDP proof)."
echo ""

echo_yellow "4.8: Preparing Bearer Token from AgentCharlie's signed VC (${AC_SIGNED_VC_FROM_NO_DELEGATE_FILE})..."
BEARER_TOKEN_CHARLIE_FROM_NO_DELEGATE=$(akta token generate --vc-file "$AC_SIGNED_VC_FROM_NO_DELEGATE_FILE" --raw-token)
echo ""

echo_yellow "Calling /map/generate API with AgentCharlie's (INVALID) Delegated VC (expecting 403)..."
API_RESPONSE_NO_DELEGATE=$(curl -s -w "\n%{http_code}" -X POST \
     -H "Authorization: Bearer $BEARER_TOKEN_CHARLIE_FROM_NO_DELEGATE" \
     -H "Content-Type: application/json" \
     -d '{"region": "script_europe_fail", "style": "script_satellite_fail"}' \
     "$MAP_GENERATE_API_URL")

HTTP_CODE_NO_DELEGATE=$(echo "$API_RESPONSE_NO_DELEGATE" | tail -n1)
API_BODY_NO_DELEGATE=$(echo "$API_RESPONSE_NO_DELEGATE" | sed '$d')

echo "Response Body (expect 403): $API_BODY_NO_DELEGATE"
echo "HTTP Status Code (expect 403): $HTTP_CODE_NO_DELEGATE"

if [ "$HTTP_CODE_NO_DELEGATE" -eq 403 ]; then
    echo_green "SUCCESS: API call with AgentCharlie's VC (delegated from non-delegable parent) correctly FAILED with HTTP 403 Forbidden!"
else
    echo_red "FAILURE: API call with AgentCharlie's VC (delegated from non-delegable parent) returned HTTP $HTTP_CODE_NO_DELEGATE, but expected 403 Forbidden."
    exit 1
fi
echo ""

echo_green "===== All tests, including 'canDelegate: false' scenario, passed! ====="
echo ""
# # Update cleanup instructions
echo_yellow "To clean up ALL generated files, you can uncomment and run the cleanup block below or manually delete:"
echo_yellow "Key files: $IA_KEY_FILE, $AB_KEY_FILE, $AC_KEY_FILE"
echo_yellow "Successful delegation files: $AB_SKILL_SUBJECT_FILE, $AB_UNSIGNED_VC_FILE, $AB_SIGNED_VC_FILE, $AC_DELEGATED_SUBJECT_FILE, $AC_UNSIGNED_VC_FILE, $AC_SIGNED_VC_FILE"
echo_yellow "Non-delegable test files: $AB_SKILL_SUBJECT_NO_DELEGATE_FILE, $AB_UNSIGNED_VC_NO_DELEGATE_FILE, $AB_SIGNED_VC_NO_DELEGATE_FILE, $AC_DELEGATED_SUBJECT_FROM_NO_DELEGATE_FILE, $AC_UNSIGNED_VC_FROM_NO_DELEGATE_FILE, $AC_SIGNED_VC_FROM_NO_DELEGATE_FILE"
echo_yellow "And the vc_store.db file if you want to reset the VC Store."
echo ""

# # Optional: Cleanup generated files
echo_yellow "Cleaning up ALL generated files..."
rm -f "$IA_KEY_FILE" "$AB_KEY_FILE" "$AC_KEY_FILE" \
      "$AB_SKILL_SUBJECT_FILE" "$AB_UNSIGNED_VC_FILE" "$AB_SIGNED_VC_FILE" \
      "$AC_DELEGATED_SUBJECT_FILE" "$AC_UNSIGNED_VC_FILE" "$AC_SIGNED_VC_FILE" \
      "$AB_SKILL_SUBJECT_NO_DELEGATE_FILE" "$AB_UNSIGNED_VC_NO_DELEGATE_FILE" "$AB_SIGNED_VC_NO_DELEGATE_FILE" \
      "$AC_DELEGATED_SUBJECT_FROM_NO_DELEGATE_FILE" "$AC_UNSIGNED_VC_FROM_NO_DELEGATE_FILE" "$AC_SIGNED_VC_FROM_NO_DELEGATE_FILE"
echo_green "Cleanup complete."

exit 0