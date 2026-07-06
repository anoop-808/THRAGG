/* ==========================================================================
   THRAGG — Data Layer
   ==========================================================================
   When integrated with the backend via DashboardGenerator, THRAGG_DATA
   is set from the embedded JSON in dashboard_template.html.
   When running standalone for development (opening frontend/index.html),
   this file provides realistic mock data.
   ========================================================================== */

/* Check if THRAGG_DATA was already set from embedded backend JSON */
if (typeof window.THRAGG_DATA === 'undefined' || window.THRAGG_DATA === null || Object.keys(window.THRAGG_DATA).length === 0) {

  console.info('[THRAGG] No embedded data found — using mock dataset.');

  window.THRAGG_DATA = {
  views: [
    "EXECUTIVE_SUMMARY",
    "RISK_PRIORITY",
    "ATTACK_CHAINS",
    "CORRELATIONS",
    "KNOWLEDGE_GRAPH",
    "MITRE_MATRIX",
    "EVIDENCE_EXPLORER"
  ],

  generated_at: "2026-07-06T14:30:00Z",

  executive_assessment: {
    id: "exec-a1b2c3d4e5",
    assessment_id: "exec-a1b2c3d4e5",
    security_posture: "Fair",
    overall_summary: "The assessment identified 3 attack paths across 4 security domains. The environment shows moderate exposure with elevated risk in network and identity domains. While no critical breaches were detected, several high-priority findings require attention to prevent potential compromise paths.",
    engine_version: "intelligence-v1",
    generated_at: "2026-07-06T14:30:00Z",
    overall_security_posture: "Fair",
    environmental_health: "Fair",
    executive_summary: "The assessment identified 3 attack paths across 4 security domains. The environment shows moderate exposure with elevated risk in network and identity domains.",
    business_impact: [
      { risk_id: "risk-001", impact: "External attack surface exposure could lead to unauthorized access to critical network services, potentially resulting in data breach or service disruption.", business_context: "SSH and RDP services exposed to untrusted networks increase the likelihood of brute-force attacks against essential infrastructure." },
      { risk_id: "risk-002", impact: "Cloud resource misconfigurations may expose sensitive data stores to unauthorized parties, with regulatory compliance implications.", business_context: "Publicly accessible storage accounts and Key Vaults represent a direct path to sensitive organizational data." },
      { risk_id: "risk-003", impact: "Weak identity controls increase the risk of account takeover and lateral movement within the environment.", business_context: "Privileged identities without multi-factor authentication create a single point of failure for authentication security." }
    ],
    top_risks: [
      { risk_id: "risk-001", risk_level: "HIGH", score: 78, summary: "Exposed SSH and RDP services on internet-facing hosts", suggested_action: "Restrict remote administrative access to approved trusted networks" },
      { risk_id: "risk-002", risk_level: "MEDIUM", score: 62, summary: "Publicly accessible cloud storage accounts", suggested_action: "Review and restrict public access to cloud storage resources" },
      { risk_id: "risk-003", risk_level: "MEDIUM", score: 55, summary: "Privileged identities without MFA", suggested_action: "Enforce multi-factor authentication for all privileged accounts" },
      { risk_id: "risk-004", risk_level: "LOW", score: 30, summary: "Repeated failed authentication attempts detected", suggested_action: "Investigate anomalous authentication patterns and implement rate limiting" },
      { risk_id: "risk-005", risk_level: "LOW", score: 25, summary: "Unpatched web application dependencies", suggested_action: "Update web application dependencies to latest stable versions" }
    ],
    top_priorities: [
      "[Network] Restrict Remote Administrative Access",
      "[Cloud] Reduce Cloud Service Exposure",
      "[Identity] Review Privileged Identity Exposure",
      "[Web] Update Application Dependencies",
      "[Logs] Configure Centralized Logging"
    ],
    executive_observations: [
      "HIGH risk attack path: External to Internal via exposed SSH services",
      "MEDIUM risk attack path: Cloud data exfiltration via public storage",
      "MEDIUM risk attack path: Privilege escalation via weak identity controls"
    ],
    executive_recommendations: [
      { id: "REC-IAM-001", title: "Review Privileged Identity Exposure", description: "Reduce exposure around privileged identities and authentication paths. Implement just-in-time privileged access and review all administrative role assignments.", priority: "High", domain: "Identity", expected_benefit: "Lower likelihood of unauthorized access to critical services", category: "Access Control", references: ["NIST CSF PR.AC", "CIS Controls 5"] },
      { id: "REC-NET-001", title: "Restrict Remote Administrative Access", description: "Limit remote administration paths to approved trusted access channels. Move SSH and RDP behind VPN or jump box solutions and restrict by source IP.", priority: "High", domain: "Network", expected_benefit: "Reduced external exposure of management services", category: "Network Security", references: ["CIS Controls 12", "NIST CSF PR.AC"] },
      { id: "REC-CLD-001", title: "Reduce Cloud Service Exposure", description: "Review externally reachable cloud services and apply least exposure principle. Ensure storage accounts, Key Vaults, and other resources are not publicly accessible.", priority: "Medium", domain: "Cloud", expected_benefit: "Reduced public attack surface for cloud-hosted services", category: "Cloud Security", references: ["CIS Controls 4", "NIST CSF PR.PT"] },
      { id: "REC-WEB-001", title: "Update Web Application Dependencies", description: "Update vulnerable web application dependencies to latest stable versions. Implement a regular dependency scanning and patching cadence.", priority: "Medium", domain: "Web", expected_benefit: "Reduced risk of exploitation through known vulnerabilities", category: "Application Security", references: ["OWASP Top 10"] },
      { id: "REC-LOG-001", title: "Configure Centralized Logging and Monitoring", description: "Deploy centralized log aggregation and monitoring. Ensure all security-relevant events are collected, retained, and monitored for suspicious activity.", priority: "Low", domain: "Logs", expected_benefit: "Improved detection and response capabilities", category: "Monitoring", references: ["NIST CSF DE.AE"] }
    ],
    assessment_scope: {
      modules_run: ["network", "cloud", "identity", "web", "logs"],
      modules_skipped: [],
      evidence_files: ["nmap_scan.xml", "azure_export.json", "entra_users.json", "zap_report.html", "auth.log"],
      assessment_limitations: ["No Windows Event Logs available", "Limited network scope (10.0.0.0/24 only)", "No endpoint detection data"],
      assessment_time: "2026-07-06T14:30:00Z"
    },
    metadata: {
      modules_used: ["network", "cloud", "identity", "web", "logs"],
      framework_commit: "a1b2c3d",
      build_version: "1.0.0"
    },
    statistics: {
      total_findings: 47,
      total_entities: 28,
      total_relationships: 64,
      total_correlations: 12,
      total_attack_chains: 3,
      risk_counts: [
        { name: "CRITICAL", count: 2 },
        { name: "HIGH", count: 8 },
        { name: "MEDIUM", count: 15 },
        { name: "LOW", count: 18 },
        { name: "INFO", count: 4 }
      ],
      top_entity_types: [
        { name: "HOST", count: 12 },
        { name: "USER", count: 8 },
        { name: "SERVICE", count: 5 },
        { name: "CLOUD_RESOURCE", count: 3 }
      ],
      top_attack_stages: [
        { name: "Initial Access", count: 4 },
        { name: "Discovery", count: 3 },
        { name: "Lateral Movement", count: 3 },
        { name: "Privilege Escalation", count: 2 }
      ],
      top_attack_categories: [
        { name: "Authentication", count: 5 },
        { name: "Network Exposure", count: 4 },
        { name: "Cloud Misconfiguration", count: 3 }
      ]
    },
    risk_distribution: [
      { name: "CRITICAL", count: 2 },
      { name: "HIGH", count: 8 },
      { name: "MEDIUM", count: 15 },
      { name: "LOW", count: 18 },
      { name: "INFO", count: 4 }
    ],
    most_critical_assets: [
      { name: "HOST", count: 12 },
      { name: "USER", count: 8 },
      { name: "SERVICE", count: 5 },
      { name: "CLOUD_RESOURCE", count: 3 }
    ],
    mitre_attack_coverage: [
      { name: "Initial Access", count: 4 },
      { name: "Discovery", count: 3 },
      { name: "Lateral Movement", count: 3 },
      { name: "Privilege Escalation", count: 2 }
    ],
    observations: [
      { id: "obs-1", category: "EXPOSURE", severity: "HIGH", confidence: "HIGH", text: "HIGH risk attack path: External to Internal via exposed SSH services on host 10.0.0.5", supporting_object_ids: ["risk-001", "chain-001", "corr-001", "corr-002"] },
      { id: "obs-2", category: "CLOUD", severity: "MEDIUM", confidence: "MEDIUM", text: "MEDIUM risk attack path: Cloud data exfiltration via publicly accessible storage accounts", supporting_object_ids: ["risk-002", "chain-002", "corr-003", "corr-004"] },
      { id: "obs-3", category: "IDENTITY", severity: "MEDIUM", confidence: "MEDIUM", text: "MEDIUM risk attack path: Privilege escalation via weak identity controls and missing MFA", supporting_object_ids: ["risk-003", "chain-003", "corr-005"] }
    ],
    primary_attack_paths: [
      { id: "obs-1", category: "EXPOSURE", severity: "HIGH", text: "External to Internal via exposed SSH services" },
      { id: "obs-2", category: "CLOUD", severity: "MEDIUM", text: "Cloud data exfiltration via public storage" }
    ],
    recommendations: [
      "Restrict Remote Administrative Access",
      "Reduce Cloud Service Exposure",
      "Review Privileged Identity Exposure",
      "Update Application Dependencies",
      "Configure Centralized Logging"
    ],
    traceability: {
      observation_to_risks: [["obs-1", ["risk-001"]], ["obs-2", ["risk-002"]], ["obs-3", ["risk-003"]]],
      observation_to_attack_chains: [["obs-1", ["chain-001"]], ["obs-2", ["chain-002"]], ["obs-3", ["chain-003"]]],
      observation_to_correlations: [["obs-1", ["corr-001", "corr-002"]], ["obs-2", ["corr-003", "corr-004"]], ["obs-3", ["corr-005"]]],
      recommendation_to_observations: [["REC-NET-001", ["obs-1"]], ["REC-CLD-001", ["obs-2"]], ["REC-IAM-001", ["obs-3"]]]
    }
  },

  framework_snapshot: {
    finding_count: 47,
    entity_count: 28,
    resolved_entity_count: 22,
    relationship_count: 64,
    snapshot_version: "1.0.0",
    generated_at: "2026-07-06T14:30:00Z",
    risk_assessments: [],
    attack_chains: [],
    correlations: []
  },

  risk_assessments: [
    {
      id: "risk-001", attack_chain_id: "chain-001", score: 78, risk_level: "HIGH",
      summary: "Exposed SSH and RDP services on internet-facing hosts",
      recommendation: "Restrict SSH and RDP access to approved trusted networks only. Implement VPN or jump box solutions.",
      created_at: "2026-07-06T14:30:00Z", policy_version: "1.0", priority_rank: 1,
      contributions: [
        { id: "cont-001", factor_name: "SeverityFactor", score: 25, max_contribution: 30, reason: "SSH and RDP services exposed to untrusted networks", source: "network" },
        { id: "cont-002", factor_name: "ConfidenceFactor", score: 18, max_contribution: 20, reason: "Service detection confirmed with high confidence via Nmap", source: "network" },
        { id: "cont-003", factor_name: "ExposureFactor", score: 15, max_contribution: 20, reason: "Two administrative services exposed on internet-facing host", source: "correlation" },
        { id: "cont-004", factor_name: "CriticalAssetFactor", score: 10, max_contribution: 15, reason: "Host contains critical application data", source: "foundation" },
        { id: "cont-005", factor_name: "MITREFactor", score: 5, max_contribution: 10, reason: "Aligns with T1021.004 (Remote Services: SSH)", source: "correlation" },
        { id: "cont-006", factor_name: "ChainLengthFactor", score: 5, max_contribution: 5, reason: "Attack chain of 4 steps indicates moderate complexity", source: "attack_chain" }
      ]
    },
    {
      id: "risk-002", attack_chain_id: "chain-002", score: 62, risk_level: "MEDIUM",
      summary: "Publicly accessible cloud storage accounts",
      recommendation: "Review and restrict public access to cloud storage resources. Enable private endpoints and firewall rules.",
      created_at: "2026-07-06T14:30:00Z", policy_version: "1.0", priority_rank: 2,
      contributions: [
        { id: "cont-007", factor_name: "SeverityFactor", score: 20, max_contribution: 30, reason: "Publicly accessible storage accounts with sensitive data", source: "cloud" },
        { id: "cont-008", factor_name: "ConfidenceFactor", score: 15, max_contribution: 20, reason: "Public access setting directly confirmed in Azure export", source: "cloud" },
        { id: "cont-009", factor_name: "ExposureFactor", score: 12, max_contribution: 20, reason: "Multiple storage containers accessible without authentication", source: "correlation" },
        { id: "cont-010", factor_name: "CriticalAssetFactor", score: 8, max_contribution: 15, reason: "Storage contains business-critical documents", source: "foundation" },
        { id: "cont-011", factor_name: "MITREFactor", score: 4, max_contribution: 10, reason: "Aligns with T1530 (Data from Cloud Storage)", source: "correlation" },
        { id: "cont-012", factor_name: "ChainLengthFactor", score: 3, max_contribution: 5, reason: "Attack chain of 3 steps", source: "attack_chain" }
      ]
    },
    {
      id: "risk-003", attack_chain_id: "chain-003", score: 55, risk_level: "MEDIUM",
      summary: "Privileged identities without MFA",
      recommendation: "Enforce multi-factor authentication for all privileged accounts immediately.",
      created_at: "2026-07-06T14:30:00Z", policy_version: "1.0", priority_rank: 3,
      contributions: [
        { id: "cont-013", factor_name: "SeverityFactor", score: 18, max_contribution: 30, reason: "Privileged identities lacking MFA protection", source: "identity" },
        { id: "cont-014", factor_name: "ConfidenceFactor", score: 15, max_contribution: 20, reason: "MFA status confirmed via Entra ID export", source: "identity" },
        { id: "cont-015", factor_name: "ExposureFactor", score: 10, max_contribution: 20, reason: "Global admin accounts without second factor", source: "correlation" },
        { id: "cont-016", factor_name: "CriticalAssetFactor", score: 7, max_contribution: 15, reason: "Global administrator role assigned", source: "foundation" },
        { id: "cont-017", factor_name: "MITREFactor", score: 3, max_contribution: 10, reason: "Aligns with T1078 (Valid Accounts)", source: "correlation" },
        { id: "cont-018", factor_name: "ChainLengthFactor", score: 2, max_contribution: 5, reason: "Attack chain of 2 steps", source: "attack_chain" }
      ]
    },
    {
      id: "risk-004", attack_chain_id: "chain-001", score: 30, risk_level: "LOW",
      summary: "Repeated failed authentication attempts detected",
      recommendation: "Investigate anomalous authentication patterns and implement rate limiting.",
      created_at: "2026-07-06T14:30:00Z", policy_version: "1.0", priority_rank: 4,
      contributions: [
        { id: "cont-019", factor_name: "SeverityFactor", score: 10, max_contribution: 30, reason: "Multiple failed login attempts from external IP", source: "logs" },
        { id: "cont-020", factor_name: "ConfidenceFactor", score: 10, max_contribution: 20, reason: "Pattern confirms to brute-force heuristic", source: "logs" },
        { id: "cont-021", factor_name: "ExposureFactor", score: 5, max_contribution: 20, reason: "Isolated to single host", source: "correlation" },
        { id: "cont-022", factor_name: "CriticalAssetFactor", score: 3, max_contribution: 15, reason: "Target host is non-critical", source: "foundation" },
        { id: "cont-023", factor_name: "MITREFactor", score: 2, max_contribution: 10, reason: "Aligns with T1110 (Brute Force)", source: "correlation" }
      ]
    },
    {
      id: "risk-005", attack_chain_id: "chain-002", score: 25, risk_level: "LOW",
      summary: "Unpatched web application dependencies",
      recommendation: "Update web application dependencies to latest stable versions.",
      created_at: "2026-07-06T14:30:00Z", policy_version: "1.0", priority_rank: 5,
      contributions: [
        { id: "cont-024", factor_name: "SeverityFactor", score: 10, max_contribution: 30, reason: "Known vulnerabilities in outdated dependencies", source: "web" },
        { id: "cont-025", factor_name: "ConfidenceFactor", score: 8, max_contribution: 20, reason: "Version detection confirmed via ZAP scan", source: "web" },
        { id: "cont-026", factor_name: "ExposureFactor", score: 4, max_contribution: 20, reason: "Application is internal-facing only", source: "correlation" },
        { id: "cont-027", factor_name: "CriticalAssetFactor", score: 3, max_contribution: 15, reason: "Application serves internal users", source: "foundation" }
      ]
    }
  ],

  attack_chains: [
    {
      id: "chain-001", chain_id: "chain-001",
      title: "External Recon to Internal Access via SSH",
      description: "An external attacker discovers exposed SSH and RDP services through network reconnaissance, then performs brute-force attacks to gain initial access to the internal network.",
      severity: "HIGH", confidence: "HIGH",
      entry_point: "10.0.0.5:22 (SSH)", target: "Internal Network",
      template_id: "T-001",
      created_at: "2026-07-06T14:30:00Z",
      correlations: ["corr-001", "corr-002"],
      entities: ["resolved-host-web-01", "resolved-service-ssh", "resolved-identity-admin"],
      relationships: ["rel-001", "rel-002", "rel-003"],
      supporting_findings: ["NMAP-10.0.0.5-22", "NMAP-10.0.0.5-3389", "LOG-AUTH-001"],
      mitre_techniques: ["T1046", "T1021.004", "T1110", "T1078"],
      steps: [
        { step_id: "chain-001-step-1", step_number: 1, order: 1, technique: "Network Service Discovery", mitre_id: "T1046", entity: "resolved-host-web-01", description: "Attacker scans external IP range and discovers host 10.0.0.5 with SSH (22) and RDP (3389) open", stage: "DISCOVERY" },
        { step_id: "chain-001-step-2", step_number: 2, order: 2, technique: "Remote Services: SSH", mitre_id: "T1021.004", entity: "resolved-service-ssh", description: "Attacker initiates SSH brute-force attack against exposed service using common credential pairs", stage: "INITIAL_ACCESS" },
        { step_id: "chain-001-step-3", step_number: 3, order: 3, technique: "Brute Force", mitre_id: "T1110", entity: "resolved-host-web-01", description: "47 failed authentication attempts recorded from external IP 203.0.113.5 over 12 minutes", stage: "CREDENTIAL_ACCESS" },
        { step_id: "chain-001-step-4", step_number: 4, order: 4, technique: "Valid Accounts", mitre_id: "T1078", entity: "resolved-identity-admin", description: "Attacker gains authenticated access using compromised admin credentials, establishing persistent foothold", stage: "INITIAL_ACCESS" }
      ],
      timeline: [
        { stage: "DISCOVERY", technique: "Network Service Discovery", mitre_id: "T1046", entity: "10.0.0.5", description: "Port scan reveals SSH and RDP services", supporting_findings: ["NMAP-10.0.0.5-22"] },
        { stage: "INITIAL_ACCESS", technique: "Remote Services: SSH", mitre_id: "T1021.004", entity: "ssh-service", description: "Brute-force attack initiated against SSH", supporting_findings: ["LOG-AUTH-001"] },
        { stage: "CREDENTIAL_ACCESS", technique: "Brute Force", mitre_id: "T1110", entity: "admin-user", description: "47 failed login attempts logged", supporting_findings: ["LOG-AUTH-001"] },
        { stage: "INITIAL_ACCESS", technique: "Valid Accounts", mitre_id: "T1078", entity: "admin-user", description: "Successful authentication with compromised credentials", supporting_findings: ["LOG-AUTH-002"] }
      ],
      chain_edges: [
        { source: "resolved-host-web-01", target: "resolved-service-ssh", relationship_type: "EXPOSES" },
        { source: "resolved-identity-admin", target: "resolved-host-web-01", relationship_type: "AUTHENTICATED_TO" }
      ],
      recommendations: ["Restrict SSH and RDP access to trusted networks", "Implement VPN requirement for remote administration"]
    },
    {
      id: "chain-002", chain_id: "chain-002",
      title: "Cloud Data Exfiltration via Public Storage",
      description: "A publicly accessible Azure storage account allows an unauthenticated attacker to enumerate and exfiltrate sensitive business data stored in blob containers.",
      severity: "MEDIUM", confidence: "MEDIUM",
      entry_point: "storageaccount.blob.core.windows.net", target: "Azure Storage",
      template_id: "T-002",
      created_at: "2026-07-06T14:30:00Z",
      correlations: ["corr-003", "corr-004"],
      entities: ["resolved-cloud-storage-prod", "resolved-cloud-storage-backup"],
      relationships: ["rel-004", "rel-005"],
      supporting_findings: ["CLD-STR-001", "CLD-STR-002"],
      mitre_techniques: ["T1530", "T1048"],
      steps: [
        { step_id: "chain-002-step-1", step_number: 1, order: 1, technique: "Data from Cloud Storage", mitre_id: "T1530", entity: "resolved-cloud-storage-prod", description: "Attacker discovers publicly accessible Azure storage account 'prodsa001' with anonymous blob access enabled", stage: "DISCOVERY" },
        { step_id: "chain-002-step-2", step_number: 2, order: 2, technique: "Data from Cloud Storage", mitre_id: "T1530", entity: "resolved-cloud-storage-prod", description: "Attacker enumerates blob containers and identifies sensitive data including financial records and customer PII", stage: "COLLECTION" },
        { step_id: "chain-002-step-3", step_number: 3, order: 3, technique: "Exfiltration Over Alternative Protocol", mitre_id: "T1048", entity: "resolved-cloud-storage-prod", description: "Attacker downloads 2.3GB of sensitive data via anonymous HTTPS requests over 15 minutes", stage: "EXFILTRATION" }
      ],
      timeline: [
        { stage: "DISCOVERY", technique: "Data from Cloud Storage", mitre_id: "T1530", entity: "prodsa001", description: "Public storage account discovered" },
        { stage: "COLLECTION", technique: "Data from Cloud Storage", mitre_id: "T1530", entity: "blob-container", description: "Sensitive data identified in containers" },
        { stage: "EXFILTRATION", technique: "Exfiltration Over Alternative Protocol", mitre_id: "T1048", entity: "external-ip", description: "2.3GB data exfiltrated via HTTPS" }
      ],
      chain_edges: [
        { source: "resolved-cloud-storage-prod", target: "resolved-cloud-storage-backup", relationship_type: "RELATED_TO" }
      ],
      recommendations: ["Disable anonymous access to storage accounts", "Enable Azure Private Endpoints for storage", "Implement data classification and labeling"]
    },
    {
      id: "chain-003", chain_id: "chain-003",
      title: "Privilege Escalation via Weak Identity Controls",
      description: "Privileged identities without multi-factor authentication create an exploitable path for credential theft and privilege escalation within the Azure AD tenant.",
      severity: "MEDIUM", confidence: "MEDIUM",
      entry_point: "Azure AD Tenant", target: "Global Administrator",
      template_id: "T-003",
      created_at: "2026-07-06T14:30:00Z",
      correlations: ["corr-005"],
      entities: ["resolved-identity-admin", "resolved-identity-user"],
      relationships: ["rel-006"],
      supporting_findings: ["ID-MFA-001", "ID-ROLE-001"],
      mitre_techniques: ["T1078", "T1098", "T1528"],
      steps: [
        { step_id: "chain-003-step-1", step_number: 1, order: 1, technique: "Valid Accounts", mitre_id: "T1078", entity: "resolved-identity-admin", description: "Attacker identifies privileged accounts lacking MFA through reconnaissance of Azure AD configuration", stage: "DISCOVERY" },
        { step_id: "chain-003-step-2", step_number: 2, order: 2, technique: "Account Manipulation", mitre_id: "T1098", entity: "resolved-identity-admin", description: "Attacker compromises a Global Administrator account without MFA through credential harvesting", stage: "PERSISTENCE" },
        { step_id: "chain-003-step-3", step_number: 3, order: 3, technique: "Steal Application Access Token", mitre_id: "T1528", entity: "resolved-identity-admin", description: "Using compromised admin credentials, attacker generates OAuth tokens for persistent access to cloud resources", stage: "CREDENTIAL_ACCESS" }
      ],
      timeline: [
        { stage: "DISCOVERY", technique: "Valid Accounts", mitre_id: "T1078", entity: "admin@thragg-demo.com", description: "Identified 3 Global Admins without MFA" },
        { stage: "PERSISTENCE", technique: "Account Manipulation", mitre_id: "T1098", entity: "Global Admin", description: "Admin account compromised via phishing" },
        { stage: "CREDENTIAL_ACCESS", technique: "Steal Application Access Token", mitre_id: "T1528", entity: "OAuth App", description: "Persistent access tokens generated" }
      ],
      chain_edges: [
        { source: "resolved-identity-admin", target: "resolved-identity-user", relationship_type: "MEMBER_OF" }
      ],
      recommendations: ["Enforce MFA for all privileged accounts", "Implement Conditional Access policies", "Review and rotate admin credentials"]
    }
  ],

  correlations: [
    {
      id: "corr-001", rule_id: "NET-EXT-001", title: "External Service Exposure",
      description: "Host 10.0.0.5 exposes SSH and RDP services to untrusted networks, creating an initial access vector.",
      severity: "HIGH", confidence: "HIGH",
      recommendation: "Restrict external access to administrative services",
      mitre: ["T1046", "T1021.004"],
      category: "Network Exposure",
      tags: ["ssh", "rdp", "external", "initial-access"],
      timestamp: "2026-07-06T14:15:00Z",
      matched_entities: [{ id: "entity-host-web-01", type: "HOST", primary_identifier: "10.0.0.5", source_module: "network" }],
      matched_relationships: ["rel-001"],
      supporting_findings: ["NMAP-10.0.0.5-22", "NMAP-10.0.0.5-3389"],
      correlation_explanation: { stage: "Initial Access", pattern: "EXTERNAL_SERVICE_EXPOSURE", matched_rules: ["NET-EXT-001"] },
      is_duplicate: false
    },
    {
      id: "corr-002", rule_id: "AUTH-BF-001", title: "Brute-Force Attack Detection",
      description: "47 failed SSH authentication attempts from external IP 203.0.113.5 targeting host 10.0.0.5.",
      severity: "MEDIUM", confidence: "HIGH",
      recommendation: "Block source IP and investigate authentication logs",
      mitre: ["T1110"],
      category: "Authentication",
      tags: ["brute-force", "ssh", "authentication"],
      timestamp: "2026-07-06T14:20:00Z",
      matched_entities: [{ id: "entity-admin-user", type: "USER", primary_identifier: "admin", source_module: "logs" }],
      matched_relationships: ["rel-002"],
      supporting_findings: ["LOG-AUTH-001"],
      correlation_explanation: { stage: "Credential Access", pattern: "BRUTE_FORCE", matched_rules: ["AUTH-BF-001"] },
      is_duplicate: false
    },
    {
      id: "corr-003", rule_id: "CLD-PUB-001", title: "Public Cloud Storage Exposure",
      description: "Azure storage account 'prodsa001' has anonymous blob access enabled, exposing sensitive data to the internet.",
      severity: "HIGH", confidence: "MEDIUM",
      recommendation: "Disable anonymous access to storage accounts",
      mitre: ["T1530"],
      category: "Cloud Misconfiguration",
      tags: ["azure", "storage", "public", "data-exposure"],
      timestamp: "2026-07-06T14:18:00Z",
      matched_entities: [{ id: "entity-cloud-storage-prod", type: "CLOUD_RESOURCE", primary_identifier: "prodsa001", source_module: "cloud" }],
      matched_relationships: ["rel-004"],
      supporting_findings: ["CLD-STR-001"],
      correlation_explanation: { stage: "Discovery", pattern: "PUBLIC_CLOUD_STORAGE", matched_rules: ["CLD-PUB-001"] },
      is_duplicate: false
    },
    {
      id: "corr-004", rule_id: "CLD-DATA-001", title: "Sensitive Data in Public Storage",
      description: "Public storage account contains financial records and customer PII in unencrypted blob containers.",
      severity: "CRITICAL", confidence: "HIGH",
      recommendation: "Immediately restrict public access and assess data exposure",
      mitre: ["T1530", "T1048"],
      category: "Data Exposure",
      tags: ["pii", "financial", "exfiltration"],
      timestamp: "2026-07-06T14:22:00Z",
      matched_entities: [{ id: "entity-cloud-storage-prod", type: "CLOUD_RESOURCE", primary_identifier: "prodsa001", source_module: "cloud" }],
      matched_relationships: ["rel-005"],
      supporting_findings: ["CLD-STR-002"],
      correlation_explanation: { stage: "Collection", pattern: "SENSITIVE_DATA_EXPOSURE", matched_rules: ["CLD-DATA-001"] },
      is_duplicate: false
    },
    {
      id: "corr-005", rule_id: "ID-MFA-001", title: "Privileged Identity Without MFA",
      description: "3 Global Administrator accounts do not have multi-factor authentication enforced, creating a credential theft risk.",
      severity: "HIGH", confidence: "MEDIUM",
      recommendation: "Enforce MFA for all privileged accounts immediately",
      mitre: ["T1078"],
      category: "Identity Risk",
      tags: ["mfa", "privileged", "identity", "authentication"],
      timestamp: "2026-07-06T14:25:00Z",
      matched_entities: [{ id: "entity-admin-user", type: "USER", primary_identifier: "admin@thragg-demo.com", source_module: "identity" }],
      matched_relationships: ["rel-006"],
      supporting_findings: ["ID-MFA-001", "ID-ROLE-001"],
      correlation_explanation: { stage: "Discovery", pattern: "MISSING_MFA", matched_rules: ["ID-MFA-001"] },
      is_duplicate: false
    }
  ],

  relationships: [
    { id: "rel-001", source_entity_id: "resolved-host-web-01", source_entity_type: "HOST", target_entity_id: "resolved-service-ssh", target_entity_type: "SERVICE", relationship_type: "EXPOSES", source_module: "network", confidence: "HIGH", supporting_findings: ["NMAP-10.0.0.5-22"], observed_at: "2026-07-06T14:10:00Z" },
    { id: "rel-002", source_entity_id: "resolved-identity-admin", source_entity_type: "USER", target_entity_id: "resolved-host-web-01", target_entity_type: "HOST", relationship_type: "AUTHENTICATED_TO", source_module: "logs", confidence: "MEDIUM", supporting_findings: ["LOG-AUTH-002"], observed_at: "2026-07-06T14:20:00Z" },
    { id: "rel-003", source_entity_id: "resolved-host-web-01", source_entity_type: "HOST", target_entity_id: "resolved-service-rdp", target_entity_type: "SERVICE", relationship_type: "EXPOSES", source_module: "network", confidence: "HIGH", supporting_findings: ["NMAP-10.0.0.5-3389"], observed_at: "2026-07-06T14:10:00Z" },
    { id: "rel-004", source_entity_id: "resolved-cloud-storage-prod", source_entity_type: "CLOUD_RESOURCE", target_entity_id: "resolved-cloud-storage-backup", target_entity_type: "CLOUD_RESOURCE", relationship_type: "RELATED_TO", source_module: "cloud", confidence: "HIGH", supporting_findings: ["CLD-STR-001"], observed_at: "2026-07-06T14:18:00Z" },
    { id: "rel-005", source_entity_id: "resolved-cloud-storage-prod", source_entity_type: "CLOUD_RESOURCE", target_entity_id: "resolved-data-financial", target_entity_type: "STORAGE", relationship_type: "CONTAINS", source_module: "cloud", confidence: "HIGH", supporting_findings: ["CLD-STR-002"], observed_at: "2026-07-06T14:22:00Z" },
    { id: "rel-006", source_entity_id: "resolved-identity-admin", source_entity_type: "USER", target_entity_id: "resolved-identity-user", target_entity_type: "USER", relationship_type: "MEMBER_OF", source_module: "identity", confidence: "HIGH", supporting_findings: ["ID-ROLE-001"], observed_at: "2026-07-06T14:25:00Z" },
    { id: "rel-007", source_entity_id: "resolved-host-web-01", source_entity_type: "HOST", target_entity_id: "resolved-cloud-storage-prod", target_entity_type: "CLOUD_RESOURCE", relationship_type: "USES", source_module: "identity", confidence: "MEDIUM", supporting_findings: ["ID-ROLE-001"], observed_at: "2026-07-06T14:25:00Z" },
    { id: "rel-008", source_entity_id: "resolved-identity-admin", source_entity_type: "USER", target_entity_id: "resolved-cloud-storage-prod", target_entity_type: "CLOUD_RESOURCE", relationship_type: "OWNS", source_module: "identity", confidence: "HIGH", supporting_findings: ["ID-ROLE-001"], observed_at: "2026-07-06T14:25:00Z" }
  ],

  resolved_entities: [
    { id: "resolved-host-web-01", entity_type: "HOST", primary_identifier: "10.0.0.5", aliases: ["web-01", "web01.internal"], source_entities: ["entity-host-web-01"], source_findings: ["NMAP-10.0.0.5-22"], source_modules: ["network"], attributes: { os: "Ubuntu 22.04", hostname: "web-01" } },
    { id: "resolved-service-ssh", entity_type: "SERVICE", primary_identifier: "SSH on 10.0.0.5:22", aliases: ["ssh"], source_entities: ["entity-service-ssh"], source_findings: ["NMAP-10.0.0.5-22"], source_modules: ["network"] },
    { id: "resolved-service-rdp", entity_type: "SERVICE", primary_identifier: "RDP on 10.0.0.5:3389", aliases: ["rdp"], source_entities: ["entity-service-rdp"], source_findings: ["NMAP-10.0.0.5-3389"], source_modules: ["network"] },
    { id: "resolved-identity-admin", entity_type: "USER", primary_identifier: "admin@thragg-demo.com", aliases: ["admin"], source_entities: ["entity-admin-user"], source_findings: ["ID-ROLE-001", "ID-MFA-001"], source_modules: ["identity", "logs"], attributes: { role: "Global Administrator", mfa_enabled: false } },
    { id: "resolved-identity-user", entity_type: "USER", primary_identifier: "user@thragg-demo.com", aliases: ["user1"], source_entities: ["entity-user"], source_findings: ["ID-ROLE-001"], source_modules: ["identity"], attributes: { role: "User", mfa_enabled: true } },
    { id: "resolved-cloud-storage-prod", entity_type: "CLOUD_RESOURCE", primary_identifier: "prodsa001", aliases: ["Production Storage"], source_entities: ["entity-cloud-storage-prod"], source_findings: ["CLD-STR-001"], source_modules: ["cloud"], attributes: { type: "Storage Account", public_access: true, region: "eastus" } },
    { id: "resolved-cloud-storage-backup", entity_type: "CLOUD_RESOURCE", primary_identifier: "backupsa001", aliases: ["Backup Storage"], source_entities: ["entity-cloud-storage-backup"], source_findings: ["CLD-STR-001"], source_modules: ["cloud"], attributes: { type: "Storage Account", public_access: false, region: "westus" } },
    { id: "resolved-data-financial", entity_type: "STORAGE", primary_identifier: "financial-records-2026", aliases: [], source_entities: [], source_findings: ["CLD-STR-002"], source_modules: ["cloud"] }
  ],

  entities: [
    { id: "entity-host-web-01", type: "HOST", primary_identifier: "10.0.0.5", source_module: "network", source_finding: "NMAP-10.0.0.5-22", confidence: "HIGH", attributes: { os: "Ubuntu 22.04" } },
    { id: "entity-service-ssh", type: "SERVICE", primary_identifier: "SSH on 10.0.0.5:22", source_module: "network", source_finding: "NMAP-10.0.0.5-22", confidence: "HIGH" },
    { id: "entity-service-rdp", type: "SERVICE", primary_identifier: "RDP on 10.0.0.5:3389", source_module: "network", source_finding: "NMAP-10.0.0.5-3389", confidence: "HIGH" },
    { id: "entity-admin-user", type: "USER", primary_identifier: "admin@thragg-demo.com", source_module: "identity", source_finding: "ID-ROLE-001", confidence: "HIGH", attributes: { role: "Global Administrator" } },
    { id: "entity-user", type: "USER", primary_identifier: "user@thragg-demo.com", source_module: "identity", source_finding: "ID-ROLE-001", confidence: "HIGH" },
    { id: "entity-cloud-storage-prod", type: "CLOUD_RESOURCE", primary_identifier: "prodsa001", source_module: "cloud", source_finding: "CLD-STR-001", confidence: "HIGH", attributes: { public_access: true } },
    { id: "entity-cloud-storage-backup", type: "CLOUD_RESOURCE", primary_identifier: "backupsa001", source_module: "cloud", source_finding: "CLD-STR-001", confidence: "HIGH" }
  ],

  findings: [
    { id: "NMAP-10.0.0.5-22", title: "Open Port 22/tcp (SSH)", severity: "MEDIUM", confidence: "HIGH", category: "Network Reconnaissance", type: "OPEN_PORT", entity_type: "HOST", asset: "10.0.0.5", source_module: "network", mitre: ["T1046"], tags: ["ssh", "remote-access"] },
    { id: "NMAP-10.0.0.5-3389", title: "Open Port 3389/tcp (RDP)", severity: "HIGH", confidence: "HIGH", category: "Network Reconnaissance", type: "OPEN_PORT", entity_type: "HOST", asset: "10.0.0.5", source_module: "network", mitre: ["T1046"], tags: ["rdp", "remote-access"] },
    { id: "LOG-AUTH-001", title: "Brute-Force Login Attempt from 203.0.113.5", severity: "HIGH", confidence: "HIGH", category: "Authentication", type: "BRUTE_FORCE", entity_type: "HOST", asset: "10.0.0.5", source_module: "logs", mitre: ["T1110"] },
    { id: "LOG-AUTH-002", title: "Successful Login: admin from 203.0.113.5", severity: "LOW", confidence: "MEDIUM", category: "Authentication", type: "SUCCESS_LOGIN", entity_type: "USER", asset: "admin", source_module: "logs", mitre: ["T1078"] },
    { id: "CLD-STR-001", title: "Public Azure Storage Account Detected", severity: "HIGH", confidence: "MEDIUM", category: "Cloud Misconfiguration", type: "PUBLIC_STORAGE", entity_type: "CLOUD_RESOURCE", asset: "prodsa001", source_module: "cloud", mitre: ["T1530"] },
    { id: "CLD-STR-002", title: "Sensitive Data in Public Storage Container", severity: "CRITICAL", confidence: "HIGH", category: "Data Exposure", type: "SENSITIVE_DATA_EXPOSED", entity_type: "STORAGE", asset: "financial-records", source_module: "cloud", mitre: ["T1530", "T1048"] },
    { id: "ID-MFA-001", title: "Privileged Identity Without MFA", severity: "HIGH", confidence: "MEDIUM", category: "Identity Risk", type: "MISSING_MFA", entity_type: "IDENTITY", asset: "admin@thragg-demo.com", source_module: "identity", mitre: ["T1078"] },
    { id: "ID-ROLE-001", title: "Excessive Privileged Role Assignment", severity: "MEDIUM", confidence: "HIGH", category: "Identity Risk", type: "EXCESSIVE_PRIVILEGE", entity_type: "IDENTITY", asset: "admin@thragg-demo.com", source_module: "identity", mitre: ["T1078"] },
    { id: "ZAP-XSS-001", title: "Cross-Site Scripting Vulnerability", severity: "HIGH", confidence: "MEDIUM", category: "Web Vulnerability", type: "XSS", entity_type: "APPLICATION", asset: "webapp.internal", source_module: "web", mitre: ["T1190"], tags: ["xss", "web"] },
    { id: "ZAP-SQL-001", title: "SQL Injection Vulnerability", severity: "CRITICAL", confidence: "MEDIUM", category: "Web Vulnerability", type: "SQL_INJECTION", entity_type: "APPLICATION", asset: "webapp.internal", source_module: "web", mitre: ["T1190"], tags: ["sqli", "web"] }
  ],

  explain_order: [
    "ExecutiveAssessment",
    "RiskAssessment",
    "AttackChain",
    "Correlation",
    "Relationship",
    "ResolvedEntity",
    "Entity",
    "Finding"
  ]
};
} /* end of mock data condition */
