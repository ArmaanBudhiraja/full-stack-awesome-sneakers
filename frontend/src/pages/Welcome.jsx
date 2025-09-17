import './Welcome.css';
import logo from '../images/logo.png';
import { Link } from "react-router-dom";
import { useState } from "react";
import AuthPopup from "../components/AuthPopup";

function Welcome() {
    const [authType, setAuthType] = useState(null);

    const AlertMsg = () => {
        alert("Please Login/SignUp First");
    }

    const switchAuthType = (type) => {
        setAuthType(type);
    }

    return (
        <div className="Body">
            <div className="Navbar">               
                <h2 className='brand_name'>awesome sneakers</h2>
                <Link className='link' onClick={() => {AlertMsg(); setAuthType("login")}}>Shop</Link>
                <Link className='link' onClick={() => {AlertMsg(); setAuthType("login")}}>Cart</Link>
                <Link className="link" onClick={() => setAuthType("login")}>Login/SignUp</Link>
            </div>
            <div className="content">
                <img src={logo} alt="logo" className='logo' />
                <h2 className='title'>Welcome to Your One-Stop Shop for Awesome Sneakers!</h2>
                <button className='shop_now' onClick={() => setAuthType("login")}>
                    Go to Login
                </button>
            </div>

            {authType && (
                <AuthPopup
                    type={authType}
                    onClose={() => setAuthType(null)}
                    onLoginSuccess={() => window.location.href="/shop"} 
                    switchType={switchAuthType}
                />
            )}
        </div>
    );
}

export default Welcome;
