// src/api/cart.js
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

export const getCartItems = async () => {
  try {
    const response = await axios.get(`${API_URL}/api/user/cart`, getAuthHeaders());
    return response.data;
  } catch (error) {
    throw error.response.data || { message: 'Failed to fetch cart items' };
  }
};

export const addToCart = async (productId, quantity, size) => {
  try {
    const response = await axios.post(
      `${API_URL}/api/user/cart`,
      { productId, quantity, size },
      getAuthHeaders()
    );
    return response.data;
  } catch (error) {
    throw error.response.data || { message: 'Failed to add item to cart' };
  }
};