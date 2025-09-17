import React, { createContext, useState, useEffect } from 'react';
import { getCartItems } from '../api/cart';

export const AuthContext = createContext();

export const AuthProvider = ({ children }) => {
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [authLoading, setAuthLoading] = useState(true); // ✅ New state variable
  const [cartItems, setCartItems] = useState([]);
  const [cartLoading, setCartLoading] = useState(true);

  useEffect(() => {
    console.log('AuthContext useEffect is running.');
    const token = localStorage.getItem('token');
    if (token) {
      setIsAuthenticated(true);
      fetchCart();
    }
    setAuthLoading(false); // ✅ Set to false after checking localStorage
  }, []);

  const fetchCart = async () => {
    try {
      setCartLoading(true);
      const items = await getCartItems();
      setCartItems(items);
    } catch (error) {
      console.error('Error fetching cart:', error);
      setCartItems([]);
    } finally {
      setCartLoading(false);
    }
  };

  const login = (token) => {
    localStorage.setItem('token', token);
    setIsAuthenticated(true);
    fetchCart();
  };

  const logout = () => {
    localStorage.removeItem('token');
    setIsAuthenticated(false);
    setCartItems([]);
  };

  const value = { isAuthenticated, authLoading, login, logout, cartItems, fetchCart, cartLoading };

  return (
    <AuthContext.Provider value={value}>
      {children}
    </AuthContext.Provider>
  );
};