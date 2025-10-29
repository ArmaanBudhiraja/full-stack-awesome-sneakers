const express = require('express');
const pool = require('../db');
const authMiddleware = require('../middleware/authMiddleware');
const router = express.Router();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

// ====================== AUTH ======================

// Signup route
router.post('/signup', async (req, res) => {
  const { name, email, password, phone } = req.body;
  try {
    const { rows } = await pool.query('SELECT * FROM users WHERE email=$1', [email]);
    if (rows.length > 0) return res.status(400).json({ message: 'User already exists' });

    const hashedPassword = await bcrypt.hash(password, 10);
    const result = await pool.query(
      'INSERT INTO users (name, email, password, phone) VALUES ($1, $2, $3, $4) RETURNING *',
      [name, email, hashedPassword, phone]
    );

    res.status(201).json({ message: 'Signup successful', user: result.rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Something went wrong' });
  }
});

// Login route
router.post('/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const { rows } = await pool.query('SELECT * FROM users WHERE email=$1', [email]);
    if (rows.length === 0) return res.status(404).json({ message: 'User not found' });

    const user = rows[0];
    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(401).json({ message: 'Incorrect password' });

    const token = jwt.sign({ id: user.id, email: user.email }, process.env.JWT_SECRET, { expiresIn: '1h' });
    res.json({ message: 'Login successful', token });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Something went wrong' });
  }
});

// ====================== CART ======================

// Get cart items
router.get('/cart', authMiddleware, async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT ci.id, ci.quantity, ci.size, p.name, p.price, p.image, p.stock
       FROM cart_items ci
       JOIN products p ON ci.product_id = p.id
       WHERE ci.user_id = $1`,
      [req.user.id]
    );
    res.json(rows);
  } catch (err) {
    console.error('Error fetching cart:', err);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

// Add item to cart + decrease stock
router.post('/cart', authMiddleware, async (req, res) => {
  const { productId, quantity, size } = req.body;
  const userId = req.user.id;

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    const productResult = await client.query('SELECT stock FROM products WHERE id = $1', [productId]);
    if (productResult.rowCount === 0) {
      await client.query('ROLLBACK');
      return res.status(404).json({ message: 'Product not found' });
    }

    const stock = productResult.rows[0].stock;
    if (stock < quantity) {
      await client.query('ROLLBACK');
      return res.status(400).json({ message: 'Not enough stock available' });
    }

    const existingItem = await client.query(
      'SELECT * FROM cart_items WHERE user_id = $1 AND product_id = $2 AND size = $3',
      [userId, productId, size]
    );

    if (existingItem.rows.length > 0) {
      await client.query(
        'UPDATE cart_items SET quantity = quantity + $1 WHERE id = $2',
        [quantity, existingItem.rows[0].id]
      );
    } else {
      await client.query(
        'INSERT INTO cart_items (user_id, product_id, quantity, size) VALUES ($1, $2, $3, $4)',
        [userId, productId, quantity, size]
      );
    }

    // decrease stock
    await client.query('UPDATE products SET stock = stock - $1 WHERE id = $2', [quantity, productId]);

    await client.query('COMMIT');
    res.status(200).json({ message: 'Item added to cart and stock updated' });
  } catch (err) {
    await client.query('ROLLBACK');
    console.error('Error adding to cart:', err);
    res.status(500).json({ error: 'Internal Server Error' });
  } finally {
    client.release();
  }
});

// Update cart item + update stock
router.put('/cart/:itemId', authMiddleware, async (req, res) => {
  const { itemId } = req.params;
  const { quantity, size } = req.body;
  const userId = req.user.id;

  const client = await pool.connect();

  try {
    await client.query('BEGIN');

    // Fetch existing cart item
    const existingItemRes = await client.query(
      'SELECT * FROM cart_items WHERE id = $1 AND user_id = $2',
      [itemId, userId]
    );

    if (existingItemRes.rowCount === 0) {
      await client.query('ROLLBACK');
      return res.status(404).json({ message: 'Cart item not found or not owned by user' });
    }

    const existingItem = existingItemRes.rows[0];
    const productId = existingItem.product_id;
    const oldQuantity = existingItem.quantity;

    // Fetch current stock for that product
    const productRes = await client.query('SELECT stock FROM products WHERE id = $1', [productId]);
    if (productRes.rowCount === 0) {
      await client.query('ROLLBACK');
      return res.status(404).json({ message: 'Product not found' });
    }

    const currentStock = productRes.rows[0].stock;

    // If quantity is changing, update stock accordingly
    if (quantity !== undefined && quantity !== oldQuantity) {
      const diff = quantity - oldQuantity; // positive = user increased quantity

      if (diff > 0 && currentStock < diff) {
        await client.query('ROLLBACK');
        return res.status(400).json({ message: 'Not enough stock available' });
      }

      // Update stock
      await client.query('UPDATE products SET stock = stock - $1 WHERE id = $2', [diff, productId]);
    }

    // Update cart item (quantity or size)
    let updateFields = [];
    let values = [];
    let idx = 1;

    if (quantity !== undefined) {
      updateFields.push(`quantity = $${idx++}`);
      values.push(quantity);
    }
    if (size !== undefined) {
      updateFields.push(`size = $${idx++}`);
      values.push(size);
    }

    if (updateFields.length === 0) {
      await client.query('ROLLBACK');
      return res.status(400).json({ message: 'No fields to update' });
    }

    values.push(itemId, userId);

    const updateRes = await client.query(
      `UPDATE cart_items 
       SET ${updateFields.join(', ')} 
       WHERE id = $${idx++} AND user_id = $${idx++}
       RETURNING *`,
      values
    );

    await client.query('COMMIT');
    res.status(200).json({
      message: 'Cart item updated successfully and stock adjusted',
      item: updateRes.rows[0],
    });
  } catch (err) {
    await client.query('ROLLBACK');
    console.error('Error updating cart:', err);
    res.status(500).json({ error: 'Internal Server Error' });
  } finally {
    client.release();
  }
});

// Delete item from cart + restore stock
router.delete('/cart/:itemId', authMiddleware, async (req, res) => {
  const { itemId } = req.params;
  const userId = req.user.id;
  const client = await pool.connect();

  try {
    await client.query('BEGIN');

    const itemResult = await client.query(
      'SELECT product_id, quantity FROM cart_items WHERE id = $1 AND user_id = $2',
      [itemId, userId]
    );

    if (itemResult.rowCount === 0) {
      await client.query('ROLLBACK');
      return res.status(404).json({ message: 'Item not found' });
    }

    const { product_id, quantity } = itemResult.rows[0];

    await client.query('DELETE FROM cart_items WHERE id = $1 AND user_id = $2', [itemId, userId]);
    await client.query('UPDATE products SET stock = stock + $1 WHERE id = $2', [quantity, product_id]);

    await client.query('COMMIT');
    res.status(200).json({ message: 'Item removed from cart and stock restored' });
  } catch (err) {
    await client.query('ROLLBACK');
    console.error('Error removing from cart:', err);
    res.status(500).json({ error: 'Internal Server Error' });
  } finally {
    client.release();
  }
});

// ====================== ADDRESS ======================

router.get('/addresses', authMiddleware, async (req, res) => {
  try {
    const { rows } = await pool.query(
      'SELECT * FROM address WHERE user_id = $1 ORDER BY created_at DESC',
      [req.user.id]
    );
    res.json(rows);
  } catch (err) {
    console.error('Error fetching addresses:', err);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

router.post('/addresses', authMiddleware, async (req, res) => {
  const { fullName, phonenumber, line1, line2, city, state, pincode } = req.body;
  try {
    const result = await pool.query(
      'INSERT INTO address (user_id, full_name, phone, line1, line2, city, state, pincode) VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING *',
      [req.user.id, fullName, phonenumber, line1, line2, city, state, pincode]
    );
    res.status(201).json(result.rows[0]);
  } catch (err) {
    console.error('Error adding address:', err);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

// ====================== CHECKOUT ======================

router.post('/checkout', authMiddleware, async (req, res) => {
  const { addressId, paymentMethod } = req.body;
  const client = await pool.connect();

  try {
    await client.query('BEGIN');

    const cartResult = await client.query(
      'SELECT product_id, quantity, size FROM cart_items WHERE user_id = $1',
      [req.user.id]
    );

    const cartItems = cartResult.rows;
    if (cartItems.length === 0) {
      await client.query('ROLLBACK');
      return res.status(400).json({ message: 'Cart is empty' });
    }

    const productIds = cartItems.map(item => item.product_id);
    const productsResult = await client.query(
      `SELECT id, price, stock FROM products WHERE id = ANY($1)`,
      [productIds]
    );

    const products = productsResult.rows;
    const priceMap = new Map(products.map(p => [p.id, p.price]));

    // Validate stock
    for (const item of cartItems) {
      const product = products.find(p => p.id === item.product_id);
      if (!product || product.stock < item.quantity) {
        await client.query('ROLLBACK');
        return res.status(400).json({ message: `Insufficient stock for product ID ${item.product_id}` });
      }
    }

    let total = 0;
    cartItems.forEach(item => {
      total += parseFloat(priceMap.get(item.product_id)) * item.quantity;
    });

    const orderResult = await client.query(
      'INSERT INTO orders (user_id, address_id, total, payment_method) VALUES ($1,$2,$3,$4) RETURNING id',
      [req.user.id, addressId, total, paymentMethod]
    );
    const orderId = orderResult.rows[0].id;

    const vals = [];
    const placeholders = [];
    let idx = 1;

    for (const it of cartItems) {
      placeholders.push(`($${idx++},$${idx++},$${idx++},$${idx++})`);
      vals.push(orderId, it.product_id, it.quantity, it.size);
    }

    await client.query(
      `INSERT INTO order_items (order_id, product_id, quantity, size)
       VALUES ${placeholders.join(',')}`,
      vals
    );

    for (const item of cartItems) {
      await client.query(`UPDATE products SET stock = stock - $1 WHERE id = $2`, [item.quantity, item.product_id]);
    }

    await client.query('DELETE FROM cart_items WHERE user_id = $1', [req.user.id]);
    await client.query('COMMIT');

    res.status(201).json({ message: 'Order placed successfully', orderId });
  } catch (err) {
    await client.query('ROLLBACK');
    console.error('Error during checkout:', err);
    res.status(500).json({ error: 'Internal Server Error' });
  } finally {
    client.release();
  }
});

// ====================== ORDERS ======================

router.get('/orders', authMiddleware, async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT o.id AS order_id, o.total, o.created_at, o.payment_method, 
              json_agg(json_build_object(
                'product_name', p.name,
                'quantity', oi.quantity,
                'size', oi.size,
                'price', p.price,
                'image', p.image,
                'description', p.description
              )) AS items
       FROM orders o
       JOIN order_items oi ON o.id = oi.order_id
       JOIN products p ON oi.product_id = p.id
       WHERE o.user_id = $1
       GROUP BY o.id
       ORDER BY o.created_at DESC`,
      [req.user.id]
    );
    res.json(rows);
  } catch (err) {
    console.error('Error fetching orders:', err);
    res.status(500).json({ message: 'Server error fetching orders' });
  }
});

module.exports = router;
