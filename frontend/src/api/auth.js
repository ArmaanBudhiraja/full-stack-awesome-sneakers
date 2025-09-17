// src/api/auth.js (Corrected)
import axios from 'axios';

// ✅ The API_URL needs the correct prefix
const API_URL = import.meta.env.VITE_API_URL;


export const signup = async (userData) => {
  try {
    const response = await axios.post(`${API_URL}/api/user/signup`, userData);
    return response.data;
  } catch (error) {
    if (error.response) {
      throw error.response.data;
    } else {
      throw { message: 'Network error: Could not connect to the server.' };
    }
  }
};

export const login = async (credentials) => {
  try {
    const response = await axios.post(`${API_URL}/api/user/login`, credentials);
    if (response.data.token) {
      localStorage.setItem('token', response.data.token);
    }
    return response.data;
  } catch (error) {
    if (error.response) {
      throw error.response.data;
    } else {
      throw { message: 'Network error: Could not connect to the server.' };
    }
  }
};