export type ScanStatus = 'PENDING' | 'RUNNING' | 'COMPLETED' | 'FAILED' | 'CANCELLED';

export type SeverityLevel = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFORMATIONAL';

export type ConfidenceLevel = 'CERTAIN' | 'FIRM' | 'TENTATIVE';

export type FindingStatus = 'DETECTED' | 'VERIFIED' | 'FALSE_POSITIVE' | 'RESOLVED';

export type CheckStatus = 'PASSED' | 'FINDINGS_DETECTED' | 'INCONCLUSIVE' | 'ERROR' | 'SKIPPED';

export interface Finding {
  id: string;
  scan_id: string;
  check_id: string;
  title: string;
  category: string;
  severity: SeverityLevel;
  confidence: ConfidenceLevel;
  status: FindingStatus;
  hostname: string;
  summary: string;
  evidence?: string | null;
  impact: string;
  remediation: string;
  references?: string | null;
  cwe_id?: string | null;
  first_observed_at: string;
  created_at: string;
}

export interface ScanCheckResult {
  id: string;
  scan_id: string;
  check_id: string;
  check_name: string;
  category: string;
  status: CheckStatus;
  duration_ms: number;
  message: string;
  error_detail?: string | null;
  executed_at: string;
}

export interface Scan {
  id: string;
  target_url: string;
  target_hostname: string;
  target_ip?: string | null;
  status: ScanStatus;
  profile: string;
  timeout_seconds: number;
  user_authorized: boolean;
  created_at: string;
  started_at?: string | null;
  completed_at?: string | null;
  duration_seconds?: number | null;
  total_checks: number;
  passed_checks: number;
  failed_checks: number;
  inconclusive_checks: number;
  total_findings: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  info_count: number;
  error_message?: string | null;
  findings?: Finding[];
  check_results?: ScanCheckResult[];
}

export interface ScanListResponse {
  items: Scan[];
  total: number;
  page: number;
  limit: number;
  total_pages: number;
}

export interface FindingListResponse {
  items: Finding[];
  total: number;
  page: number;
  limit: number;
  total_pages: number;
}

export interface CommonMisconfiguration {
  title: string;
  severity: SeverityLevel;
  category: string;
  count: number;
}

export interface HistoricalTrend {
  date: string;
  hostname: string;
  critical: number;
  high: number;
  medium: number;
  low: number;
  informational: number;
  total: number;
}

export interface DashboardSummary {
  total_scans: number;
  completed_scans: number;
  total_findings: number;
  critical_findings: number;
  high_findings: number;
  medium_findings: number;
  low_findings: number;
  info_findings: number;
  severity_distribution: Record<SeverityLevel, number>;
  category_distribution: Record<string, number>;
  recent_scans: Scan[];
  common_misconfigurations: CommonMisconfiguration[];
  historical_trends: HistoricalTrend[];
}

export interface SecurityMethodologyCheck {
  check_id: string;
  name: string;
  category: string;
  description: string;
}

export interface SeverityRule {
  severity: SeverityLevel;
  criteria: string;
  sla: string;
}

export interface SecurityMethodology {
  title: string;
  version: string;
  checks: SecurityMethodologyCheck[];
  severity_model: SeverityRule[];
  operational_boundaries: Record<string, string>;
}
