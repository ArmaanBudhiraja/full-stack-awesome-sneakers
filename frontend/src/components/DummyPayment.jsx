import React, { useState } from 'react';
import './DummyPayment.css';

const DummyPayment = ({ onPaymentSuccess, onPaymentFailure }) => {
  const [cardNumber, setCardNumber] = useState("");
  const [cvv, setCvv] = useState("");
  const [expiryDate, setExpiryDate] = useState("");
  const [cardName, setCardName]= useState("");
  const [processing, setProcessing] = useState(false);

  const handlePayment = async () => {
    // This is the dummy logic. Replace with real API call if needed.
    setProcessing(true);
    setTimeout(() => {
        if (cardNumber.length === 16 && cvv.length === 3) {
            alert('Dummy payment successful!');
            onPaymentSuccess();
        } else {
            alert('Invalid card details.');
            onPaymentFailure('Invalid card details.');
        }
        setProcessing(false);
    }, 1500);
  };

  return (
    <div className="card-details">
      <h3 className="card-details-heading">Card Details</h3>
      <input
        className="card-number"
        type="text"
        placeholder="Card Number"
        value={cardNumber}
        onChange={(e) => setCardNumber(e.target.value)}
        maxLength="16"
        required
      />
      <br/>
      <input
        className="card-expiry"
        type="text"
        placeholder="MM/YY"
        value={expiryDate}
        onChange={(e) => setExpiryDate(e.target.value)}
        maxLength="5"
        required
      />
      <input
        className="card-cvv"
        type="text"
        placeholder="CVV"
        value={cvv}
        onChange={(e) => setCvv(e.target.value)}
        maxLength="3"
        required
      />
      <br/>
      <input
        className="card-name"
        type="text"
        placeholder="Name"
        value={cardName}
        onChange={(e) => setCardName(e.target.value)}
        required
      />
    </div>
  );
};

export default DummyPayment;