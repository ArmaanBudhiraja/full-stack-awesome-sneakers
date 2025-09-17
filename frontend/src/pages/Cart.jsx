import React, { useContext } from "react";
import { Link } from "react-router-dom";
import "./Cart.css";
import EmptyCart from '../images/cart_logo.png';
import { useNavigate } from "react-router-dom";
import { AuthContext } from '../context/AuthContext';
import axios from 'axios';

// The API URL should be consistent across all your API files. 
// Use the port your backend is currently running on.
const API_URL = import.meta.env.VITE_API_URL; // Change this if your backend port changes

const Cart = () => {
  const { cartItems, fetchCart, cartLoading } = useContext(AuthContext);
  const navigate = useNavigate();

  const total = cartItems.reduce((sum, item) => sum + item.price * item.quantity, 0);

  const updateCartItem = async (itemId, updates) => {
    try {
      const token = localStorage.getItem('token');
      await axios.put(`${API_URL}/api/user/cart/${itemId}`, updates, {
        headers: { Authorization: `Bearer ${token}` }
      });
      await fetchCart(); // Re-fetch to get updated cart from backend
    } catch (error) {
      alert(`Error updating cart: ${error.response?.data?.message || error.message}`);
    }
  };

  const handleQuantityChange = (itemId, newQuantity) => {
    if (newQuantity < 1) return;
    updateCartItem(itemId, { quantity: newQuantity });
  };

  const handleSizeChange = (itemId, newSize) => {
    updateCartItem(itemId, { size: newSize });
  };

  const removeItem = async (itemId) => {
    try {
      const token = localStorage.getItem('token');
      await axios.delete(`${API_URL}/api/user/cart/${itemId}`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      await fetchCart();
      alert('Item removed from cart!');
    } catch (error) {
      alert(`Failed to remove item: ${error.response?.data?.message || error.message}`);
    }
  };

  const Navi = () => {
    navigate("/shop");
  };

  if (cartLoading) {
    return <div>Loading cart...</div>;
  }

  return (
    <div className="body_c">
      <div className="Navbar">
        <h2 className='brand_name'>awesome sneakers</h2>
        <Link className='link' to='/home'>Home</Link>
        <Link className='link' to='/shop'>Shop</Link>
        <Link className='link' to='/cart'>Cart</Link>
        <Link className='link' to='/orders'>Orders</Link>
      </div>
      {cartItems.length === 0 ? (
        <div className="empty-cart">
          <img src={EmptyCart} alt="Logo" className="EmptyCartLogo" />
          <p className="empty-cart-text">Hey, it feels light here</p>
          <p className="empty-cart-text-down">There's nothing in your bag. Let's add some items</p>
          <div className="link-box">
            <button onClick={Navi} className="link-to-shop">Add Items From Shop</button>
          </div>
        </div>
      ) : (
        <>
          <div className="cart-items">
            {cartItems.map((item) => (
              <div key={item.id} className="cart-item">
                <img src={item.image} alt={item.name} className="cart-img" />
                <div className="cart-content">
                  <div className="cart-details">
                    <h3 className="cart-name">{item.name}</h3>
                    <div className="size-price">
                      <div>
                        <label className="cart-size">
                          Size:
                          <select
                            value={item.size}
                            onChange={(e) => handleSizeChange(item.id, e.target.value)}
                          >
                            <option value="7">7</option>
                            <option value="8">8</option>
                            <option value="9">9</option>
                            <option value="10">10</option>
                          </select>
                        </label>
                      </div>
                      <div>
                        <p className="cart-price">Price: ₹{item.price}</p>
                      </div>
                    </div>
                  </div>

                  <div className="cart-quantity">
                    <button className="quantity-button-minus"
                      onClick={() => handleQuantityChange(item.id, item.quantity - 1)}
                    >
                      -
                    </button>
                    <span className="cart-item-quantity">{item.quantity}</span>
                    <button className="quantity-button-plus"
                      onClick={() => handleQuantityChange(item.id, item.quantity + 1)}
                    >
                      +
                    </button>
                  </div>
                </div>
                <div>
                  <button
                    className="remove-btn"
                    onClick={() => removeItem(item.id)}
                  >
                    ✕
                  </button>
                </div>
              </div>
            ))}
          </div>

          <div className="cart-summary">
            <h2 className="cart-heading">PRICE DETAILS ({cartItems.reduce((sum, item) => sum + item.quantity, 0)} item)</h2>
            <div className="cart-box1">
              <h2 className="total-mrp">Total MRP</h2>
              <h2 className="total-mrp-price">₹{total}</h2>
            </div>
            <div className="cart-box2">
              <h2 className="platform">Platform fee</h2>
              <h2 className="platform-fee">₹25</h2>
            </div>
            <hr></hr>
            <div className="cart-box3">
              <h2 className="cart-total">Total Amount</h2>
              <h2 className="cart-total-price">₹{total + 25}</h2>
            </div>
            <Link to="/checkout">
              <button className="checkout-btn">Proceed to Checkout</button>
            </Link>
          </div>
        </>
      )}
    </div>
  );
};

export default Cart;