import './Shop.css'
import HeadImg from '../images/headimg.avif';
import {Link} from "react-router-dom"
import HoverImage from '../components/HoverImage';
import Popup from "../components/Popup";
import { getProducts } from '../api/products';
import React, { useState, useEffect } from 'react';

function Shop({ addToCart }){
  const [activePopup, setActivePopup] = useState(null);
  const [choice, setChoice] = useState("Recommended");
  const [products, setProducts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    const fetchProducts = async () => {
      try {
        const productsData = await getProducts();
        setProducts(productsData);
      } catch (err) {
        setError(err.message);
      } finally {
        setLoading(false);
      }
    };
    fetchProducts();
  }, []);

  if (loading) return <div>Loading products...</div>;
  if (error) return <div>Error: {error}</div>;

  return (
    <div className='Body_S'>
       <div className="Navbar">
            <h2 className='brand_name'>awesome sneakers</h2>
            <Link className='link' to='/home'>Home</Link>
            <Link className='link' to='/shop'>Shop</Link>
            <Link className='link' to='/cart'>Cart</Link>
            <Link className='link' to='/orders'>Orders</Link>
        </div>
        <div className='body_s'>
          <div className='content_s'>
            <br></br>
            <img src={HeadImg} alt="headimage" className='headimg_s'/>
            <br></br>
            <h2 className='Shop_text'>Shop</h2>
            <br></br>
            <div className='filter'>
              <h3 className='h3_left'>{products.length} Products</h3>
              <h3>Sort by: </h3>
              <div className='Box'>
                <select className='options' value={choice} onChange={(e) => setChoice(e.target.value)}>
                  <option value="Recommended">Recommended</option>
                  <option value="Newest">Newest</option>
                  <option value="Price_low_to_high">Price (low to high)</option>
                  <option value="Price_high_to_low">Price (high to low)</option>
                  <option value="Name_A_Z">Name A-Z</option>
                  <option value="Name_Z-A">Name Z-A</option>
                </select>
              </div>
            </div>
            <div className='Products_list'>
              {products.map(product => (
              <div key={product.id} className='box'>
                <div className='Product_box'>
                  <HoverImage 
                    defaultSrc={`${import.meta.env.VITE_API_URL}${product.image}`} 
                    hoverSrc={`${import.meta.env.VITE_API_URL}${product.image2}`} 
                    alt={product.name} 
                    className='image'
                  />
                  <br></br>
                  <h4 className='shoe_name'>{product.name}</h4>
                  <h4 className='shoe_price'>₹{product.price}</h4>
                  <button className='addcart' onClick={() => setActivePopup(product)}>Add To Cart</button>
                </div>
              </div>
            ))}
            </div>
          </div>
          <br></br>
        </div>
        {activePopup && (
        <Popup
          product={activePopup}
          addToCart={addToCart}
          onClose={() => setActivePopup(null)}
        />
      )}
    </div>
  )
}

export default Shop;
