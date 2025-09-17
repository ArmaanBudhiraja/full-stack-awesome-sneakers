import React, { useState, useEffect, useContext } from 'react';
import { Link } from 'react-router-dom';
import { AuthContext } from '../context/AuthContext';
import { getOrders } from '../api/orders';
import { getProducts } from '../api/products';
import './Orders.css';

const Orders = () => {
  const { isAuthenticated } = useContext(AuthContext);
  const [orders, setOrders] = useState([]);
  const [loading, setLoading] = useState(true);
  const [products, setProducts] = useState([]);
  const [error, setError] = useState(null);

  useEffect(() => {
    const fetchUserOrders = async () => {
      if (isAuthenticated) {
        try {
          const data = await getOrders();
          setOrders(data);
        } catch (err) {
          setError(err.message);
          console.error('Failed to fetch orders:', err);
        } finally {
          setLoading(false);
        }
      } else {
        setLoading(false);
      }
    };

    fetchUserOrders();

    const fetchProducts = async () => {
      try {
        const productsData = await getProducts();
        setProducts(productsData);
      } catch (err) {
        setError(err.message);
      }
    };

    fetchProducts();
  }, [isAuthenticated]);

  if (loading) return <div>Loading your orders...</div>;
  if (error) return <div>Error: {error}</div>;

  return (
    <div className="orders-body">
      <div className="Navbar">
        <h2 className="brand_name">awesome sneakers</h2>
        <Link className="link" to="/home">Home</Link>
        <Link className="link" to="/shop">Shop</Link>
        <Link className="link" to="/cart">Cart</Link>
        <Link className="link" to="/orders">Orders</Link>
      </div>

      <div className="orders-container">
        <h2 className="order-heading">Your Past Orders</h2>
        {orders.length === 0 ? (
          <p>You have not placed any orders yet.</p>
        ) : (
          orders.map((order, index) => (
            <div key={order.order_id} className="order-card">
              <div className="order-header">
                <h3 className="order-number-heading">Order #{index + 1}</h3>
                <p className="ordered-date">
                  on {new Date(order.created_at).toLocaleDateString()}
                </p>
                <p>Total: ₹{order.total}</p>
              </div>
              <div className="order-items">
                <h4 className="items-heading">Items:</h4>
                {Array.isArray(order.items) && order.items.map((item, itemIndex) => {
                  return (
                    <div key={itemIndex} className="order-item">
                        <img
                          src={item.image}
                          alt={item.name}
                          className="order-item-image"
                        />
                      <div>
                        <p>{item.product_name} ({item.size}) - Qty: {item.quantity}</p>
                        <p>Price: ₹{item.price}</p>
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  );
};

export default Orders;
