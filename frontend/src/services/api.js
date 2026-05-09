import axios from 'axios';

const API_URL = 'http://localhost:8000';

export const getAlerts = () => axios.get(`${API_URL}/alerts`);
