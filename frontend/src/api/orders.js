// src/api/orders.js
import axios from 'axios';

const API_URL = import.meta.env.VITE_API_URL;

const getAuthHeaders = () => {
  const token = localStorage.getItem('token');
  return {
    headers: {
      Authorization: `Bearer ${token}`,
    },
    withCredentials: true,
  };
};

export const getOrders = async () => {
  try {
    console.log("Token being sent:", localStorage.getItem("token"));
    const response = await axios.get(`${API_URL}/api/user/orders`, getAuthHeaders());
    return response.data;
  } catch (error) {
    throw error.response?.data || { message: 'Failed to fetch orders' };
  }
};
