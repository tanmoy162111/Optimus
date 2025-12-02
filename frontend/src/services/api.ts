import axios, { AxiosInstance, AxiosError, AxiosResponse } from 'axios';
import { config } from '@/config';
import type { 
  Scan, 
  Vulnerability, 
  Tool, 
  ToolResolution,
  DashboardStats,
  Report,
  MLModel,
  SystemHealth,
  ApiResponse,
  PaginatedResponse 
} from '@/types';

// ============================================
// API Service
// ============================================

class ApiService {
  private client: AxiosInstance;
  
  constructor() {
    this.client = axios.create({
      baseURL: config.apiUrl,
      timeout: 30000,
      headers: {
        'Content-Type': 'application/json',
      },
    });
    
    // Request interceptor
    this.client.interceptors.request.use(
      (config) => {
        // Add auth token if available
        const token = localStorage.getItem('auth_token');
        if (token) {
          config.headers.Authorization = `Bearer ${token}`;
        }
        return config;
      },
      (error) => Promise.reject(error)
    );
    
    // Response interceptor
    this.client.interceptors.response.use(
      (response) => response,
      (error: AxiosError) => {
        // Handle common errors
        if (error.response?.status === 401) {
          // Handle unauthorized
          localStorage.removeItem('auth_token');
          window.location.href = '/login';
        }
        return Promise.reject(error);
      }
    );
  }
  
  // ============================================
  // Scan Endpoints
  // ============================================
  
  scan = {
    /**
     * Start a new scan
     */
    start: async (target: string, options?: Record<string, unknown>): Promise<Scan> => {
      const response = await this.client.post<Scan>('/api/scan/start', { target, ...options });
      return response.data;
    },
    
    /**
     * Get scan status
     */
    getStatus: async (scanId: string): Promise<Scan> => {
      const response = await this.client.get<Scan>(`/api/scan/status/${scanId}`);
      return response.data;
    },
    
    /**
     * Stop a running scan
     */
    stop: async (scanId: string): Promise<{ success: boolean }> => {
      const response = await this.client.post<{ success: boolean }>(`/api/scan/stop/${scanId}`);
      return response.data;
    },
    
    /**
     * Pause a running scan
     */
    pause: async (scanId: string): Promise<{ success: boolean }> => {
      const response = await this.client.post<{ success: boolean }>(`/api/scan/pause/${scanId}`);
      return response.data;
    },
    
    /**
     * Resume a paused scan
     */
    resume: async (scanId: string): Promise<{ success: boolean }> => {
      const response = await this.client.post<{ success: boolean }>(`/api/scan/resume/${scanId}`);
      return response.data;
    },
    
    /**
     * Get scan results
     */
    getResults: async (scanId: string): Promise<Scan> => {
      const response = await this.client.get<Scan>(`/api/scan/results/${scanId}`);
      return response.data;
    },
    
    /**
     * List all scans
     */
    list: async (params?: { 
      page?: number; 
      limit?: number; 
      status?: string 
    }): Promise<PaginatedResponse<Scan> & { active_count: number }> => {
      const response = await this.client.get<PaginatedResponse<Scan> & { active_count: number }>(
        '/api/scan/list', 
        { params }
      );
      return response.data;
    },
    
    /**
     * Execute a specific tool
     */
    executeTool: async (
      scanId: string, 
      tool: string, 
      target: string, 
      options?: Record<string, unknown>
    ): Promise<{ success: boolean; message: string }> => {
      const response = await this.client.post<{ success: boolean; message: string }>(
        '/api/scan/execute-tool',
        { scan_id: scanId, tool, target, options }
      );
      return response.data;
    },
    
    /**
     * Get findings for a scan
     */
    getFindings: async (scanId: string): Promise<Vulnerability[]> => {
      const response = await this.client.get<{ findings: Vulnerability[] }>(
        `/api/scan/${scanId}/findings`
      );
      return response.data.findings;
    },
  };
  
  // ============================================
  // Tool Endpoints
  // ============================================
  
  tools = {
    /**
     * Get available tools
     */
    getAvailable: async (category?: string): Promise<Tool[]> => {
      const response = await this.client.get<{ tools: Tool[] }>(
        '/api/tools/available',
        { params: { category } }
      );
      return response.data.tools;
    },
    
    /**
     * Get tool categories
     */
    getCategories: async (): Promise<string[]> => {
      const response = await this.client.get<{ categories: string[] }>('/api/tools/categories');
      return response.data.categories;
    },
    
    /**
     * Resolve a tool (hybrid system)
     */
    resolve: async (
      toolName: string, 
      task: string, 
      target: string, 
      context?: Record<string, unknown>
    ): Promise<ToolResolution> => {
      const response = await this.client.post<ToolResolution>('/api/tools/resolve', {
        tool_name: toolName,
        task,
        target,
        context,
      });
      return response.data;
    },
    
    /**
     * Scan system for tools
     */
    scan: async (): Promise<{ tools_found: number; statistics: Record<string, number> }> => {
      const response = await this.client.post<{ tools_found: number; statistics: Record<string, number> }>(
        '/api/tools/scan'
      );
      return response.data;
    },
    
    /**
     * Research a tool
     */
    research: async (toolName: string): Promise<{
      tool_name: string;
      description: string;
      github_url?: string;
      basic_usage: string;
      examples: string[];
      confidence: number;
    }> => {
      const response = await this.client.get(`/api/tools/research/${toolName}`);
      return response.data;
    },
    
    /**
     * Get tool inventory
     */
    getInventory: async (): Promise<{
      tools: Tool[];
      statistics: Record<string, number>;
    }> => {
      const response = await this.client.get('/api/tools/inventory');
      return response.data;
    },
  };
  
  // ============================================
  // Report Endpoints
  // ============================================
  
  reports = {
    /**
     * Generate report
     */
    generate: async (scanId: string, format: 'json' | 'pdf' | 'html' = 'json'): Promise<Report> => {
      const response = await this.client.post<Report>(`/api/reports/generate/${scanId}`, { format });
      return response.data;
    },
    
    /**
     * Get report
     */
    get: async (reportId: string): Promise<Report> => {
      const response = await this.client.get<Report>(`/api/reports/${reportId}`);
      return response.data;
    },
    
    /**
     * Download report
     */
    download: async (reportId: string, format: 'json' | 'pdf' | 'html'): Promise<Blob> => {
      const response = await this.client.get(`/api/reports/${reportId}/download`, {
        params: { format },
        responseType: 'blob',
      });
      return response.data;
    },
    
    /**
     * List reports
     */
    list: async (): Promise<Report[]> => {
      const response = await this.client.get<{ reports: Report[] }>('/api/reports');
      return response.data.reports;
    },
  };
  
  // ============================================
  // Dashboard Endpoints
  // ============================================
  
  dashboard = {
    /**
     * Get dashboard statistics
     */
    getStats: async (): Promise<DashboardStats> => {
      const response = await this.client.get<DashboardStats>('/api/dashboard/stats');
      return response.data;
    },
    
    /**
     * Get recent activity
     */
    getActivity: async (limit = 10): Promise<{
      scans: Scan[];
      findings: Vulnerability[];
    }> => {
      const response = await this.client.get('/api/dashboard/activity', { params: { limit } });
      return response.data;
    },
  };
  
  // ============================================
  // Metrics Endpoints
  // ============================================
  
  metrics = {
    /**
     * Get ML metrics
     */
    getML: async (): Promise<{
      models: MLModel[];
      performance: Record<string, number>;
    }> => {
      const response = await this.client.get('/api/metrics/ml');
      return response.data;
    },
    
    /**
     * Get RL metrics
     */
    getRL: async (): Promise<{
      episodes: number;
      average_reward: number;
      tool_selection_accuracy: number;
    }> => {
      const response = await this.client.get('/api/metrics/rl');
      return response.data;
    },
    
    /**
     * Get scan history metrics
     */
    getScanHistory: async (): Promise<{
      total_scans: number;
      successful_scans: number;
      average_duration: number;
      findings_over_time: { date: string; count: number }[];
    }> => {
      const response = await this.client.get('/api/metrics/scan-history');
      return response.data;
    },
    
    /**
     * Get system metrics
     */
    getSystem: async (): Promise<SystemHealth> => {
      const response = await this.client.get<SystemHealth>('/api/metrics/system');
      return response.data;
    },
  };
  
  // ============================================
  // Training Endpoints
  // ============================================
  
  training = {
    /**
     * Start training job
     */
    start: async (config: {
      datasets: string[];
      train_rl?: boolean;
      epochs?: number;
    }): Promise<{ job_id: string }> => {
      const response = await this.client.post<{ job_id: string }>('/api/training/start', config);
      return response.data;
    },
    
    /**
     * Get training status
     */
    getStatus: async (jobId: string): Promise<{
      status: 'running' | 'completed' | 'failed';
      progress: number;
      metrics?: Record<string, number>;
    }> => {
      const response = await this.client.get(`/api/training/status/${jobId}`);
      return response.data;
    },
    
    /**
     * List models
     */
    listModels: async (): Promise<MLModel[]> => {
      const response = await this.client.get<{ models: MLModel[] }>('/api/training/models');
      return response.data.models;
    },
  };
}

// Export singleton instance
export const api = new ApiService();
export default api;
