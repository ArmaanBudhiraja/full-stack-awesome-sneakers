import React, { useState, useContext, useEffect } from "react";
import { Link, useNavigate } from "react-router-dom";
import { AuthContext } from "../context/AuthContext";
import { addAddress, placeOrder, getUserAddresses } from "../api/checkout";
import DummyPayment from "../components/DummyPayment"; // ✅ Import the new component
import axios from 'axios';
import "./Checkout.css";

const API_URL = import.meta.env.VITE_API_URL;


const Checkout = () => {
  const { cartItems, fetchCart } = useContext(AuthContext);
  const navigate = useNavigate();

  const [addresses, setAddresses] = useState([]);
  const [selectedAddress, setSelectedAddress] = useState(null);
  const [showPopup, setShowPopup] = useState(false);
  const [paymentMethod, setPaymentMethod] = useState("cod");

  const [fullName, setFullName] = useState("");
  const [phonenumber, setPhonenumber] = useState("");
  const [addressLine1, setAddressLine1] = useState("");
  const [addressLine2, setAddressLine2] = useState("");
  const [city, setCity] = useState("");
  const [state, setState] = useState("");
  const [pincode, setPincode] = useState("");

  const total = cartItems.reduce((sum, item) => sum + item.price * item.quantity, 0);

  useEffect(() => {
    const fetchAddresses = async () => {
      try {
        const data = await getUserAddresses();
        setAddresses(data);
        if (data.length > 0) {
          setSelectedAddress(data[0].id);
        }
      } catch (err) {
        alert(err.message);
      }
    };
    fetchAddresses();
  }, []);

  const handleAddAddress = async () => {
    if (!fullName || !addressLine1 || !city || !state || !pincode) {
      alert("Please fill all required fields!");
      return;
    }
    try {
      const newAddress = await addAddress({
        fullName, phonenumber, line1: addressLine1, line2: addressLine2, city, state, pincode
      });
      setAddresses([...addresses, newAddress]);
      setSelectedAddress(newAddress.id);
      setShowPopup(false);
      setFullName(""); setPhonenumber(""); setAddressLine1(""); setAddressLine2(""); setCity(""); setState(""); setPincode("");
    } catch (error) {
      alert(error.message);
    }
  };

  const handlePlaceOrder = async () => {
    if (!selectedAddress) {
      alert("Please select a shipping address!");
      return;
    }
    if (paymentMethod === "cod") {
      try {
        await placeOrder(selectedAddress, 'cod');
        await fetchCart();
        alert("Order placed successfully!");
        navigate("/home");
      } catch (error) {
        alert(`Failed to place order: ${error.message}`);
      }
    } else if (paymentMethod === "card") {
      try {
        await placeOrder(selectedAddress, 'card');
        await fetchCart();
        alert("Order placed successfully!");
        navigate("/home");
      } catch (error) {
        alert(`Failed to place order: ${error.message}`);
      }
    }
  };

  if (cartItems.length === 0) {
    return <p>Your cart is empty!</p>;
  }

  return (
    <div className="checkout-body">
      <div className="Navbar">
        <h2 className='brand_name'>awesome sneakers</h2>
        <Link className='link' to='/home'>Home</Link>
        <Link className='link' to='/shop'>Shop</Link>
        <Link className='link' to='/cart'>Cart</Link>
      </div>
      <div className="main-checkout-content">
        <div className="checkout-form">
          <h3 className="shipping-text">Shipping Address</h3>
          {addresses.map((addr) => (
            <div className="address" key={addr.id}>
              <label className="address-radio-label">
                <input
                  type="radio"
                  name="shippingAddress"
                  checked={selectedAddress === addr.id}
                  onChange={() => setSelectedAddress(addr.id)}
                />
                <span className="address-data-name">{addr.full_name}</span>
                <br/>
                <span className="address-data">{addr.line1}, {addr.line2 ? addr.line2 + "," : ""}</span>
                <br/>
                <span className="address-data">{addr.city}, {addr.state} - {addr.pincode}</span>
                <br/>
                <span className="address-data">Mobile:</span><span className="addres-data-phone"> {addr.phone}</span>
              </label>
            </div>
          ))}
          <button className="add-address-btn" onClick={() => setShowPopup(true)}>+ Add Address</button>
          {showPopup && (
            <div className="checkout-body auth-popup-overlay">
              <div className="auth-popup-box">
                <button className="close-button" onClick={() => setShowPopup(false)}>&times;</button>
                <h3 style={{ fontWeight: 600 }}>Add Address</h3>
                <input className="input-value-text" type="text" placeholder="Full Name" value={fullName} onChange={(e) => setFullName(e.target.value)} />
                <input className="input-value-text" type="tel" placeholder="Phone Number" value={phonenumber} onChange={(e) => setPhonenumber(e.target.value)} />
                <input className="input-value-text" type="text" placeholder="Address Line 1" value={addressLine1} onChange={(e) => setAddressLine1(e.target.value)} />
                <input className="input-value-text" type="text" placeholder="Address Line 2 (Optional)" value={addressLine2} onChange={(e) => setAddressLine2(e.target.value)} />
                <input className="input-value-text" type="text" placeholder="City" value={city} onChange={(e) => setCity(e.target.value)} />
                <input className="input-value-text" type="text" placeholder="State" value={state} onChange={(e) => setState(e.target.value)} />
                <input className="input-value-text" type="text" placeholder="Pincode" value={pincode} onChange={(e) => setPincode(e.target.value)} />
                <button className="save-address-btn" onClick={handleAddAddress}>Save Address</button>
              </div>
            </div>
          )}
          <h3 className="payment-text">Payment Method</h3>
          <div className="address">
            <label>
              <input type="radio" name="payment" value="card" checked={paymentMethod === "card"} onChange={(e) => setPaymentMethod(e.target.value)} />
              Credit/Debit Card
            </label>
            {paymentMethod === "card" && (
              <div className="card-details">
                <DummyPayment /> {/* ✅ Replace the placeholder with your component */}
              </div>
            )}
            <label>
              <input type="radio" name="payment" value="cod" checked={paymentMethod === "cod"} onChange={(e) => setPaymentMethod(e.target.value)} />
              Cash on Delivery
            </label>
            <button className="place-order-btn" onClick={handlePlaceOrder}>
              Place Order
            </button>
          </div>
        </div>
        <div className="checkout-cart">
          <h3 className="order-summary-text">Order Summary</h3>
          {cartItems.map((item) => (
            <div key={`${item.id}-${item.size}`} className="checkout-item">
              <div className="checkout-item-details">
                <p className="item-name-checkout">{item.name}</p>
                <p className="item-price-checkout">₹{item.price * item.quantity}</p>
              </div>
              <p className="item-size-checkout">Size: {item.size}</p>
            </div>
          ))}
          <div className="total-mrp-checkout-box">
            <h4 className="total-mrp-checkout">Total MRP </h4>
            <h4 className="total-mrp-amount-checkout">₹{total}</h4>
          </div>
          <br/>
          <div className="platform-checkout-box">
            <h4 className="platform-checkout">Platform Fee</h4>
            <h4 className="platform-amount-checkout"> ₹25</h4>
          </div>
          <hr/>
          <div className="final-amount-checkout">
            <h3 className="total-amount-text">Total Amount</h3>
            <h3 className="total-amount-price">₹{total + 25}</h3>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Checkout;