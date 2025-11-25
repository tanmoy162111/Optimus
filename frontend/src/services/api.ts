import axios from 'axios';

const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:5000';

export const api = {
  scan: {
    start: (target: string) => 
      axios.post(`${API_URL}/api/scan/start`, { target }),
    
    getStatus: (scanId: string) => 
      axios.get(`${API_URL}/api/scan/status/${scanId}`),
    
    stop: (scanId: string) => 
      axios.post(`${API_URL}/api/scan/stop/${scanId}`),
    
    getResults: (scanId: string) => 
      axios.get(`${API_URL}/api/scan/results/${scanId}`),
    
    list: () => 
      axios.get(`${API_URL}/api/scan/list`)
  },
  
  training: {
    start: (datasets: string[], trainRl: boolean) => 
      axios.post(`${API_URL}/api/training/start`, { datasets, train_rl: trainRl }),
    
    getStatus: (jobId: string) => 
      axios.get(`${API_URL}/api/training/status/${jobId}`),
    
    listModels: () => 
      axios.get(`${API_URL}/api/training/models`)
  },
  
  metrics: {
    getML: () => 
      axios.get(`${API_URL}/api/metrics/ml`),
    
    getRL: () => 
      axios.get(`${API_URL}/api/metrics/rl`),
    
    getScanHistory: () => 
      axios.get(`${API_URL}/api/metrics/scan-history`),
    
    getSystem: () => 
      axios.get(`${API_URL}/api/metrics/system`)
  }
};
