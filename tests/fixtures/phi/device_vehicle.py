# Synthetic PHI fixture: Device Identifiers and Vehicle Identification Numbers
# Device IDs (UDI) and VINs are HIPAA identifiers when linked to a patient.
# Expected findings: minimum 2 (DEVICE_ID / VIN entity types)

# Vehicle Identification Number (fictional — fails VIN check-digit on purpose)
vehicle_vin = "1HGBH41JXMN109186"

# Unique Device Identifier (UDI-DI format per FDA)
implant_device_id = "00844588003288"
udi_full = "(01)00844588003288(10)A213B1C2"

device_record = {
    "pacemaker_serial": "DEV-2024-SN-778899",
    "udi": "00844588003288",
}
