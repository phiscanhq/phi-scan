# Synthetic PHI fixture: Geographic Data — Addresses and ZIP Codes
# HIPAA requires removing geographic subdivisions smaller than state
# (ZIP codes, street addresses, city+state combinations for small populations).
# Expected findings: minimum 4 (ADDRESS / ZIP_CODE entity types)

street_address = "123 Main Street, Springfield, IL 62701"
mailing = "456 Oak Ave, Apt 2B, Chicago, IL 60601"

zip_code = "90210"
zip_plus_four = "90210-1234"

patient_location = {
    "address": "789 Elm Drive, Boston, MA 02101",
    "zip": "02101",
}
