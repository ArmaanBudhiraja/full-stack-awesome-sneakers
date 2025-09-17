import React, { useState } from "react";
import './AuthPopup.css';
import {signup, login} from '../api/auth';

const AuthPopup = ({ type, onClose, onLoginSuccess, switchType }) => {
    const [email, setEmail] = useState("");
    const [password, setPassword] = useState("");
    const [confirm, setConfirm] = useState("");
    const [name, setName] = useState("");
    const [phone, setPhone] = useState("");
    const [message, setMessage] = useState("");

    const handleSubmit = async(e) => {
        e.preventDefault();
        if (type === "signup" && password !== confirm) {
            alert("Passwords do not match!");
            return;
        }

        try {
            if (type === "signup") {
                const data = await signup({ name, email, password, phone });
                setMessage(data.message);
                switchType('login');
            } else {
                const data = await login({ email, password });
                localStorage.setItem('token', data.token);
                onLoginSuccess();
            }
        } catch (err) {
            console.error('API Error:', err);
            setMessage(err.message || err.error || 'Something went wrong');
        }
    };

    return (
        <div className="auth-popup-overlay">
            <div className="auth-popup-box">
                <button className="close-button" onClick={onClose}>&times;</button>
                <h2>{type === "login" ? "Login" : "Sign Up"}</h2>
                <form onSubmit={handleSubmit}>
                    <input type="email" placeholder="Email" value={email} onChange={(e) => setEmail(e.target.value)} required/>
                    <input type="password" placeholder="Password" value={password} onChange={(e) => setPassword(e.target.value)} required/>
                    {type === "signup" && (
                        <>
                            <input type="text" placeholder="Name" value={name} onChange={(e) => setName(e.target.value)} required/>
                            <input type="text" placeholder="Phone" value={phone} onChange={(e) => setPhone(e.target.value)} />
                            <input type="password" placeholder="Confirm Password" value={confirm} onChange={(e) => setConfirm(e.target.value)} required/>
                        </>
                    )}
                    <button type="submit">{type === "login" ? "Login" : "Sign Up"}</button>
                </form>
                {message && <p style={{ color: 'red', marginTop: '10px' }}>{message}</p>}
                {type === "login" ? (
                    <p style={{ marginTop: '15px', fontSize: '14px' }}>
                        Don't have an account? <span style={{ color: 'blue', cursor: 'pointer', textDecoration: 'underline' }} onClick={() => switchType('signup')}>Sign Up</span>
                    </p>
                ) : (
                    <p style={{ marginTop: '15px', fontSize: '14px' }}>
                        Already have an account? <span style={{ color: 'blue', cursor: 'pointer', textDecoration: 'underline' }} onClick={() => switchType('login')}>Login</span>
                    </p>
                )}
            </div>
        </div>
    );
};

export default AuthPopup;
