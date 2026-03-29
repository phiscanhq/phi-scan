# Synthetic clean fixture: Version numbers and numeric codes — zero PHI expected
# Regex patterns that match SSN (NNN-NN-NNNN) also match version strings and
# numeric codes of similar shape. Detectors must distinguish SSNs from these
# patterns by context (variable names, surrounding tokens, reserved ranges).
# Expected findings: 0

# Semantic version strings — NNN.NN.NNNN shape is NOT an SSN
PACKAGE_VERSION = "1.12.2024"
SCHEMA_VERSION = "2.0.1"
API_VERSION = "10.4.300"

# Database schema / migration IDs — numeric codes not in SSN format
MIGRATION_ID = "20240315001"
SCHEMA_REVISION = "003"

# HTTP status codes — never PHI
HTTP_OK = 200
HTTP_NOT_FOUND = 404
HTTP_INTERNAL_SERVER_ERROR = 500

# Port numbers and counts — never PHI
DEFAULT_PORT = 8080
MAX_CONNECTIONS = 1024
WORKER_COUNT = 4

# Colour hex codes — shape collision with numeric patterns
PRIMARY_COLOR = "#3A86FF"
SECONDARY_COLOR = "#FF006E"
BACKGROUND_COLOR = "#FFFFFF"

# Checksums and hashes — not person-linked identifiers
FILE_CHECKSUM = "d41d8cd98f00b204e9800998ecf8427e"
BUILD_HASH = "a3f5bc12"

# Timestamps as integers — not DOB or SSN
EPOCH_MS = 1_711_584_000_000
CACHE_TTL_SECONDS = 3_600
