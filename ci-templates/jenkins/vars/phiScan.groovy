// phi-scan:ignore-file
// Shared library step: vars/phiScan.groovy
//
// Place this file in a Jenkins Shared Library repository under vars/.
// Then call it from any Jenkinsfile:
//
//   @Library('your-shared-lib') _
//   phiScan()
//
// Parameters (all optional):
//   path              — directory to scan (default: '.')
//   diffRef           — git ref to diff against (default: auto-detect from CHANGE_TARGET)
//   outputDir         — where to write report files (default: 'phi-scan-results')
//   postComment       — post PR comment with findings (default: true on PR builds)
//   setStatus         — set commit status (default: true on PR builds)
//   failOnViolation   — fail the build on violations (default: true)

def call(Map config = [:]) {
    def path            = config.get('path', '.')
    def outputDir       = config.get('outputDir', 'phi-scan-results')
    def postComment     = config.get('postComment', env.CHANGE_ID ? true : false)
    def setStatus       = config.get('setStatus', env.CHANGE_ID ? true : false)
    def failOnViolation = config.get('failOnViolation', true)

    def diffRef = config.get('diffRef', env.CHANGE_TARGET ? "origin/${env.CHANGE_TARGET}" : '')

    sh "mkdir -p ${outputDir}"

    def flags = [
        diffRef  ? "--diff ${diffRef}"                           : '',
        "--output sarif --report-path ${outputDir}/phi-scan.sarif",
        "--output json  --report-path ${outputDir}/phi-scan.json",
        postComment ? '--post-comment' : '',
        setStatus   ? '--set-status'   : '',
    ].findAll { it }.join(' \\\n            ')

    def exitCode = sh(
        script: "phi-scan scan ${path} \\\n            ${flags}",
        returnStatus: true
    )

    // 6C.12: Warnings NG — SARIF severity maps to error/warning/note levels
    recordIssues(
        enabledForFailure: true,
        tools: [
            sarif(
                pattern: "${outputDir}/phi-scan.sarif",
                id: 'phi-scan',
                name: 'PHI/PII Scan'
            )
        ]
    )

    // 6C.13: Checks API — inline annotations on GitHub/Bitbucket PR builds
    if (env.CHANGE_ID) {
        try {
            publishChecks(
                name: 'phi-scan',
                title: 'PHI/PII Scan',
                summary: exitCode == 0 ? 'No PHI/PII violations.' : 'Violations detected — see Warnings NG.',
                conclusion: exitCode == 0 ? 'SUCCESS' : 'FAILURE',
                detailsURL: env.BUILD_URL ?: ''
            )
        } catch (Exception checksException) {
            echo "WARNING: Checks API plugin unavailable — inline annotations skipped: ${checksException.message}"
        }
    }

    // 6C.14: Build description for at-a-glance status in build history
    try {
        // NOTE: phiScanReportFilename is intentionally duplicated in
        // Jenkinsfile — shared libraries cannot import constants from a
        // Jenkinsfile, so each file maintains its own copy.
        def phiScanReportFilename = "phi-scan.json"
        def phiScanJsonPath = "${outputDir}/${phiScanReportFilename}"
        if (fileExists(phiScanJsonPath)) {
            def scanResult = readJSON(file: phiScanJsonPath)
            currentBuild.description = scanResult.is_clean
                ? 'PhiScan: Clean'
                : "PhiScan: ${scanResult.findings?.size()} findings (${scanResult.severity_counts?.HIGH ?: 0} HIGH)"
        }
    } catch (Exception jsonException) {
        // Intentional: build description is cosmetic — a JSON parse failure
        // must not propagate as a build error. The scan result is already
        // reported via exit code, SARIF artifacts, and Warnings NG.
        echo "WARNING: phi-scan JSON summary unavailable — ${jsonException.message}"
    }

    archiveArtifacts(
        artifacts: "${outputDir}/**",
        allowEmptyArchive: true,
        fingerprint: true
    )

    if (failOnViolation && exitCode != 0) {
        error("phi-scan: PHI/PII violations detected (exit ${exitCode})")
    }

    return exitCode
}
