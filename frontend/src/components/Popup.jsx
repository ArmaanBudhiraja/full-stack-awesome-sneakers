// Popup.jsx (updated)
import React, { useState, useContext } from "react";
import HoverImage from "../components/HoverImage";
import "./Popup.css";
import { useNavigate } from "react-router-dom";
import { addToCart as addToCartAPI } from '../api/cart';
import { AuthContext } from '../context/AuthContext';

const Popup = ({ product, onClose }) => { // Accept a single 'product' prop
    const [choice, setChoice] = useState("select");
    const [quantity, setQuantity] = useState(1);
    const navigate = useNavigate();
    const { fetchCart } = useContext(AuthContext); // Get fetchCart from context

    const increaseQuantity = () => setQuantity(q => q + 1);
    const decreaseQuantity = () => setQuantity(q => (q > 1 ? q - 1 : 1));

    const handleAddToCart = async () => {
        if (choice === "select") {
            alert("Please select a size!");
            return;
        }

        try {
            await addToCartAPI(product.id, quantity, choice);
            await fetchCart(); // Re-fetch the cart to update the global state
            onClose();
            navigate("/cart");
        } catch (error) {
            alert(`Failed to add to cart: ${error.message}`);
        }
    };

    return (
        <div className="popup-overlay">
            <div className="popup-box">
                <div className="image_box_p">
                    <HoverImage
                        defaultSrc={product.image}
                        hoverSrc={product.image2} 
                        alt={product.name}
                        className="image_p"
                    />
                </div>
                <div className="popup-content">
                    <div className="content_p">
                        <h2 className="name_p">{product.name}</h2>
                        <h3 className="price_p">₹{product.price}</h3>
                        <h4 className="size_p">Size*</h4>
                        <select
                            className="options_p"
                            value={choice}
                            onChange={(e) => setChoice(e.target.value)}
                        >
                            <option value="select" disabled>Select</option>
                            <option value="7">7</option>
                            <option value="8">8</option>
                            <option value="9">9</option>
                            <option value="10">10</option>
                        </select>
                        <h4 className="quantity_p">Quantity*</h4>
                        <div className="quantity-controls">
                            <button className="qty-btn" onClick={decreaseQuantity}>-</button>
                            <span className="qty-value">{quantity}</span>
                            <button className="qty-btn" onClick={increaseQuantity}>+</button>
                        </div>
                        <button className='addcart_p' onClick={handleAddToCart}>Add To Cart</button>
                    </div>
                    <button className="close-button" onClick={onClose}>
                        &times;
                    </button>
                </div>
            </div>
        </div>
    );
};

export default Popup;