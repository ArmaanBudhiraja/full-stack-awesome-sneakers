# FullStack Payment Portal

A full-stack e-commerce web application for sneakers, featuring user authentication, shopping cart, checkout with multiple payment methods, and address management.

The project is split into **Frontend** and **Backend** and uses **PostgreSQL** for the database.

---

## Table of Contents

* [Technologies Used](#technologies-used)
* [Features](#features)
* [Project Structure](#project-structure)
* [Setup & Installation](#setup--installation)
* [Environment Variables](#environment-variables)
* [Deployment](#deployment)
* [API Endpoints](#api-endpoints)
* [License](#license)

---

# Technologies Used

* **Frontend:** React.js, Vite, Axios, React Router
* **Backend:** Node.js, Express.js
* **Database:** PostgreSQL
* **Deployment:** Render (Web Service + Static Site + PostgreSQL)

---

# Features

* User authentication and JWT-based authorization
* Add/remove items in the cart
* Checkout with **Cash on Delivery** and **Card Payment** (dummy payment)
* Address management (add, select, save shipping addresses)
* Order summary with platform fee calculation
* Responsive design

---

## Project Structure

```
visa-payment-portal/
│
├─ backend/
│  ├─ routes/
│  ├─ middleware/
│  ├─ images/
│  ├─ server.js
│  ├─ package.json
│  └─ .env
│
├─ frontend/
│  ├─ src/
│  │  ├─ components/
│  │  ├─ pages/
│  │  ├─ context/
│  │  ├─ api/
│  │  └─ main.jsx
│  ├─ package.json
│  └─ vite.config.js
│
└─ README.md
```

---

## Setup & Installation

### Backend

1. Navigate to the backend folder:

```bash
cd backend
```

2. Install dependencies:

```bash
npm install
```

3. Create a `.env` file with:

```env
DATABASE_URL="your_postgres_url"
JWT_SECRET=supersecretkey123
NODE_ENV=development
PORT=4004
```

4. Run the backend server:

```bash
npm run dev
```

It will run on `http://localhost:4004`.

### Frontend

1. Navigate to the frontend folder:

```bash
cd frontend
```

2. Install dependencies:

```bash
npm install
```

3. Create a `.env` file with:

```env
VITE_API_URL=http://localhost:4004/api
```

4. Run the frontend:

```bash
npm run dev
```

It will run on `http://localhost:5173` (or 5174).

---

## Deployment

1. **Frontend:** Deploy as a **Static Site** on Render. Build using:

```bash
npm run build
```

2. **Backend:** Deploy as a **Web Service** on Render. Ensure `.env` variables are configured.
3. **Database:** Use **PostgreSQL** on Render.

> ⚠️ Make sure CORS is configured in the backend to allow your frontend domain.

---

## Environment Variables

| Variable       | Description                       |
| -------------- | --------------------------------- |
| DATABASE\_URL  | Postgres connection URL           |
| JWT\_SECRET    | Secret key for JWT authentication |
| NODE\_ENV      | `development` or `production`     |
| PORT           | Port number for backend           |
| VITE\_API\_URL | Frontend API base URL             |

---

## API Endpoints

### User Routes

| Endpoint             | Method | Description           |
| -------------------- | ------ | --------------------- |
| `/api/user/register` | POST   | Register a new user   |
| `/api/user/login`    | POST   | Login user            |
| `/api/user/cart`     | GET    | Get user's cart items |
| `/api/user/cart`     | POST   | Add item to cart      |
| `/api/user/cart/:id` | PUT    | Update item quantity  |
| `/api/user/cart/:id` | DELETE | Remove item from cart |

### Product Routes

| Endpoint            | Method | Description       |
| ------------------- | ------ | ----------------- |
| `/api/products`     | GET    | Get all products  |
| `/api/products/:id` | GET    | Get product by ID |

---

## License

This project is licensed under the MIT License.
