SHELL := /bin/bash
.PHONY: api install-dev clean generate-models download-schema

# Variables
A2A_API_URL := https://raw.githubusercontent.com/google/A2A/refs/heads/main/specification/json/a2a.json
DOWNLOAD_DIR := _build
JSON_FILE_BASENAME := a2a.json
JSON_FILE_PATH := $(DOWNLOAD_DIR)/$(JSON_FILE_BASENAME)

MODEL_OUTPUT_DIR := akta/a2a
MODEL_FILE_BASENAME := models.py
MODEL_FILE_PATH := $(MODEL_OUTPUT_DIR)/$(MODEL_FILE_BASENAME)

# Default target
api: install-dev $(MODEL_FILE_PATH)

# Target to generate Python models from the JSON schema
# This target depends on the JSON_FILE_PATH being present.
$(MODEL_FILE_PATH): $(JSON_FILE_PATH)
	@echo "Ensuring output directory $(MODEL_OUTPUT_DIR) exists..."
	@mkdir -p $(MODEL_OUTPUT_DIR)
	@echo "Generating Python models from $(JSON_FILE_PATH) to $(MODEL_FILE_PATH)..."
	uv run datamodel-codegen --output-model-type pydantic_v2.BaseModel --input-file-type jsonschema --input $(JSON_FILE_PATH) --output $(MODEL_FILE_PATH)
	@echo "Models generated successfully."

# Target to download the A2A JSON schema
$(JSON_FILE_PATH):
	@echo "Ensuring download directory $(DOWNLOAD_DIR) exists..."
	@mkdir -p $(DOWNLOAD_DIR)
	@echo "Downloading A2A JSON schema from $(A2A_API_URL) to $(JSON_FILE_PATH)..."
	curl -L -o $(JSON_FILE_PATH) $(A2A_API_URL)
	@echo "Schema downloaded successfully."

# Phony target to explicitly trigger model generation
generate-models: $(MODEL_FILE_PATH)

# Phony target to explicitly trigger schema download
download-schema: $(JSON_FILE_PATH)

# Target to install development dependencies
install-dev:
	@echo "Installing development dependencies using uv..."
	uv pip install .[dev]
	@echo "Development dependencies installed."

# Target to clean generated files and directories
clean:
	@echo "Cleaning generated files..."
	@rm -f $(MODEL_FILE_PATH)
	-@rmdir $(MODEL_OUTPUT_DIR) >/dev/null 2>&1 || true # Remove directory if empty, suppress errors
	@rm -f $(JSON_FILE_PATH)
	-@rmdir $(DOWNLOAD_DIR) >/dev/null 2>&1 || true # Remove directory if empty, suppress errors
	@echo "Clean complete."

