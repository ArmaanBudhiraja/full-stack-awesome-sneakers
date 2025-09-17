// src/api/checkout.js
import axios from 'axios';

const API_URL = import.meta.env.VITE_API_URL;

const getAuthHeaders = () => {
  const token = localStorage.getItem('token');
  return {
    headers: {
      Authorization: `Bearer ${token}`,
    },
  };
};

export const placeOrder = async (addressId, paymentMethod) => {
  try {
    const response = await axios.post(
      `${API_URL}/api/user/checkout`,
      { addressId, paymentMethod },
      getAuthHeaders()
    );
    return response.data;
  } catch (error) {
    throw error.response.data || { message: 'Failed to place order' };
  }
};

export const getUserAddresses = async () => {
  try {
    const response = await axios.get(`${API_URL}/api/user/addresses`, getAuthHeaders());
    return response.data;
  } catch (error) {
    throw error.response.data || { message: 'Failed to fetch addresses' };
  }
};

export const addAddress = async (addressData) => {
  try {
    const response = await axios.post(`${API_URL}/api/user/addresses`, addressData, getAuthHeaders());
    return response.data;
  } catch (error) {
    throw error.response.data || { message: 'Failed to add address' };
  }
};
