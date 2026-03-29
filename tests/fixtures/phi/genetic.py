# Synthetic PHI fixture: Genetic Identifiers
# Covered under HIPAA Safe Harbor + GINA + GDPR Art. 9 (biometric/genetic data).
# rsIDs (dbSNP), VCF variant notation, and gene panel names are all PHI-adjacent.
# Expected findings: minimum 3 (GENETIC_ID entity type)

# dbSNP rsID (Single Nucleotide Polymorphism identifier)
snp_id = "rs1234567"
variant_snp = "rs9876543"

# VCF-format variant notation: chromosome:position:ref:alt
vcf_variant = "chr1:925952:G:A"
vcf_deletion = "chr17:43094692:CTTT:C"

gene_panel = {
    "panel_name": "BRCA1/BRCA2 Comprehensive Panel",
    "rsids": ["rs80357906", "rs80357711"],
}
