import axios from 'axios';
import {
  Scan,
  ScanListResponse,
  Finding,
  FindingListResponse,
  DashboardSummary,
  SecurityMethodology,
  SeverityLevel,
  ScanStatus,
} from '../types';

const apiClient = axios.create({
  baseURL: '/api',
  headers: {
    'Content-Type': 'application/json',
  },
});

export const api = {
  // Health
  getHealth: async () => {
    const res = await apiClient.get('/health');
    return res.data;
  },

  // Dashboard
  getDashboardSummary: async (): Promise<DashboardSummary> => {
    const res = await apiClient.get<DashboardSummary>('/dashboard/summary');
    return res.data;
  },

  seedDemoData: async () => {
    const res = await apiClient.post('/dashboard/seed');
    return res.data;
  },

  // Scans
  createScan: async (payload: {
    target_url: string;
    user_authorized: boolean;
    profile?: string;
    timeout_seconds?: number;
  }): Promise<Scan> => {
    const res = await apiClient.post<Scan>('/scans', payload);
    return res.data;
  },

  getScans: async (params?: {
    page?: number;
    limit?: number;
    status?: ScanStatus;
    hostname?: string;
  }): Promise<ScanListResponse> => {
    const res = await apiClient.get<ScanListResponse>('/scans', { params });
    return res.data;
  },

  getScan: async (scanId: string): Promise<Scan> => {
    const res = await apiClient.get<Scan>(`/scans/${scanId}`);
    return res.data;
  },

  cancelScan: async (scanId: string): Promise<Scan> => {
    const res = await apiClient.post<Scan>(`/scans/${scanId}/cancel`);
    return res.data;
  },

  deleteScan: async (scanId: string): Promise<void> => {
    await apiClient.delete(`/scans/${scanId}`);
  },

  // Findings
  getFindings: async (params?: {
    page?: number;
    limit?: number;
    search?: string;
    severity?: SeverityLevel;
    category?: string;
    hostname?: string;
    scan_id?: string;
  }): Promise<FindingListResponse> => {
    const res = await apiClient.get<FindingListResponse>('/findings', { params });
    return res.data;
  },

  getFinding: async (findingId: string): Promise<Finding> => {
    const res = await apiClient.get<Finding>(`/findings/${findingId}`);
    return res.data;
  },

  // Methodology
  getMethodology: async (): Promise<SecurityMethodology> => {
    const res = await apiClient.get<SecurityMethodology>('/methodology');
    return res.data;
  },

  // Reports
  getReportPdfUrl: (scanId: string): string => `/api/scans/${scanId}/report.pdf`,
  getReportJsonUrl: (scanId: string): string => `/api/scans/${scanId}/report.json`,
};
