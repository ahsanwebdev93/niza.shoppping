const http = require("node:http");
const { readFile } = require("node:fs/promises");
const { randomBytes, scryptSync, timingSafeEqual } = require("node:crypto");
const path = require("node:path");
const { database } = require("./lib/database");

const host = "127.0.0.1";
const port = Number(process.env.PORT) || 4173;
const categories = ["Shoes", "Bags", "Watches", "Makeup", "Luggage", "Other"];
const statuses = ["New", "Confirmed", "Shipped", "Delivered", "Cancelled"];
const sessions = new Map();
const loginAttempts = new Map();
const sessionLifetime = 12 * 60 * 60 * 1000;

const files = new Map([
  ["/", ["index.html", "text/html; charset=utf-8"]],
  ["/css/styles.css", ["css/styles.css", "text/css; charset=utf-8"]],
  ["/js/store.js", ["js/store.js", "text/javascript; charset=utf-8"]],
  ["/admin", ["admin/index.html", "text/html; charset=utf-8"]],
  ["/admin/", ["admin/index.html", "text/html; charset=utf-8"]],
  ["/admin/admin.css", ["admin/admin.css", "text/css; charset=utf-8"]],
  ["/admin/admin.js", ["admin/admin.js", "text/javascript; charset=utf-8"]]
]);

class HttpError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

function sendJson(response, status, value) {
  response.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff"
  });
  response.end(JSON.stringify(value));
}

async function readJson(request) {
  let body = "";
  for await (const chunk of request) {
    body += chunk;
    if (body.length > 100_000) throw new HttpError(413, "Request body is too large.");
  }
  if (!body) return {};
  try {
    const parsed = JSON.parse(body);
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
      throw new HttpError(400, "A JSON object is required.");
    }
    return parsed;
  } catch {
    throw new HttpError(400, "Invalid JSON request.");
  }
}

function asProduct(row) {
  return { ...row, active: Boolean(row.active) };
}

function requireAdmin(request) {
  const authorization = request.headers.authorization || "";
  const token = authorization.startsWith("Bearer ") ? authorization.slice(7) : "";
  const session = sessions.get(token);
  if (!session || session.expiresAt <= Date.now()) {
    if (token) sessions.delete(token);
    throw new HttpError(401, "Please sign in again.");
  }
  return session;
}

function validateProduct(value, partial = false) {
  const result = {};
  if (!partial || "name" in value) {
    if (typeof value.name !== "string" || !value.name.trim() || value.name.trim().length > 150) {
      throw new HttpError(400, "Enter a product name up to 150 characters.");
    }
    result.name = value.name.trim();
  }
  if (!partial || "category" in value) {
    if (!categories.includes(value.category)) throw new HttpError(400, "Choose a valid product category.");
    result.category = value.category;
  }
  for (const field of ["price_pkr", "stock"]) {
    if (!partial || field in value) {
      if (!Number.isSafeInteger(value[field]) || value[field] < 0) {
        throw new HttpError(400, `${field === "price_pkr" ? "Price" : "Stock"} must be a non-negative whole number.`);
      }
      result[field] = value[field];
    }
  }
  if ("emoji" in value) {
    if (typeof value.emoji !== "string" || [...value.emoji].length > 8) {
      throw new HttpError(400, "Emoji must be 8 characters or fewer.");
    }
    result.emoji = value.emoji || "🛍️";
  } else if (!partial) {
    result.emoji = "🛍️";
  }
  if ("image_url" in value) {
    if (value.image_url !== null) {
      try {
        if (!["http:", "https:"].includes(new URL(value.image_url).protocol)) throw new Error();
      } catch {
        throw new HttpError(400, "Image URL must be a valid HTTP or HTTPS address.");
      }
    }
    result.image_url = value.image_url;
  } else if (!partial) {
    result.image_url = null;
  }
  if ("active" in value) {
    if (typeof value.active !== "boolean") throw new HttpError(400, "Availability must be true or false.");
    result.active = value.active ? 1 : 0;
  } else if (!partial) {
    result.active = 1;
  }
  if (partial && Object.keys(result).length === 0) throw new HttpError(400, "Nothing to update.");
  return result;
}

function productFromRequest(value, partial = false) {
  return validateProduct(value, partial);
}

function insertProduct(product) {
  return database.prepare(`
    INSERT INTO products (name, category, price_pkr, stock, emoji, image_url, active)
    VALUES (@name, @category, @price_pkr, @stock, @emoji, @image_url, @active)
  `).run(product);
}

function updateProduct(id, product) {
  const keys = Object.keys(product);
  const assignments = keys.map((key) => `${key} = @${key}`).join(", ");
  return database.prepare(`UPDATE products SET ${assignments} WHERE id = @id`)
    .run({ ...product, id });
}

function listOrders(status) {
  const orders = status
    ? database.prepare("SELECT * FROM orders WHERE status = ? ORDER BY created_at DESC, id DESC LIMIT 200").all(status)
    : database.prepare("SELECT * FROM orders ORDER BY created_at DESC, id DESC LIMIT 200").all();
  const getItems = database.prepare("SELECT name, price_pkr, qty FROM order_items WHERE order_id = ?");
  return orders.map((order) => ({ ...order, items: getItems.all(order.id) }));
}

function verifyLogin(email, password) {
  const admin = database.prepare("SELECT * FROM admins WHERE email = ?").get(email.toLowerCase());
  if (!admin) return false;
  const expected = Buffer.from(admin.password_hash, "hex");
  const actual = scryptSync(password, Buffer.from(admin.password_salt, "hex"), expected.length);
  return expected.length === actual.length && timingSafeEqual(expected, actual);
}

function checkLoginLimit(request) {
  const ip = request.socket.remoteAddress || "unknown";
  const now = Date.now();
  const attempts = (loginAttempts.get(ip) || []).filter((time) => now - time < 15 * 60 * 1000);
  loginAttempts.set(ip, attempts);
  if (attempts.length >= 10) throw new HttpError(429, "Too many sign-in attempts. Try again in 15 minutes.");
  return ip;
}

function recordLoginFailure(ip) {
  const attempts = loginAttempts.get(ip) || [];
  attempts.push(Date.now());
  loginAttempts.set(ip, attempts);
}

async function handleApi(request, response, url) {
  const route = url.pathname;
  const method = request.method;

  if (method === "GET" && route === "/api/health") {
    sendJson(response, 200, { ok: true });
    return;
  }

  if (method === "GET" && route === "/api/products") {
    const category = url.searchParams.get("category");
    if (category && category !== "All" && !categories.includes(category)) {
      throw new HttpError(400, "Unknown product category.");
    }
    const rows = category && category !== "All"
      ? database.prepare("SELECT id, name, category, price_pkr, stock, emoji, image_url FROM products WHERE active = 1 AND category = ? ORDER BY id").all(category)
      : database.prepare("SELECT id, name, category, price_pkr, stock, emoji, image_url FROM products WHERE active = 1 ORDER BY id").all();
    sendJson(response, 200, rows);
    return;
  }

  const productMatch = route.match(/^\/api\/products\/(\d+)$/);
  if (method === "GET" && productMatch) {
    const product = database.prepare("SELECT id, name, category, price_pkr, stock, emoji, image_url FROM products WHERE id = ? AND active = 1")
      .get(Number(productMatch[1]));
    if (!product) throw new HttpError(404, "Product not found.");
    sendJson(response, 200, product);
    return;
  }

  if (method === "POST" && route === "/api/orders") {
    const order = await readJson(request);
    const name = typeof order.customerName === "string" ? order.customerName.trim() : "";
    const phone = typeof order.phone === "string" ? order.phone.trim() : "";
    const address = typeof order.address === "string" ? order.address.trim() : "";
    const city = typeof order.city === "string" ? order.city.trim() : "";
    const paymentMethod = order.paymentMethod;
    if (name.length < 2 || name.length > 100) throw new HttpError(400, "Enter your full name.");
    if (!/^(\+92|0)?3\d{9}$|^\+?\d{9,15}$/.test(phone)) throw new HttpError(400, "Enter a valid phone number.");
    if (address.length < 5 || address.length > 300) throw new HttpError(400, "Enter a delivery address.");
    if (city.length < 2 || city.length > 60) throw new HttpError(400, "Enter your city.");
    if (!["cod", "bank_transfer", "wallet"].includes(paymentMethod)) throw new HttpError(400, "Choose a payment method.");
    if (!Array.isArray(order.items) || order.items.length < 1 || order.items.length > 30) throw new HttpError(400, "Your cart is empty or contains too many products.");

    const quantities = new Map();
    for (const item of order.items) {
      if (!Number.isSafeInteger(item.productId) || item.productId < 1 || !Number.isSafeInteger(item.qty) || item.qty < 1 || item.qty > 20) {
        throw new HttpError(400, "Invalid product or quantity in your cart.");
      }
      quantities.set(item.productId, (quantities.get(item.productId) || 0) + item.qty);
    }

    database.exec("BEGIN IMMEDIATE");
    try {
      const getProduct = database.prepare("SELECT id, name, price_pkr, stock FROM products WHERE id = ? AND active = 1");
      const purchased = [...quantities].map(([id, qty]) => {
        const product = getProduct.get(id);
        if (!product) throw new HttpError(400, "One or more products are no longer available.");
        if (product.stock < qty) throw new HttpError(409, `Not enough stock for ${product.name}.`);
        return { ...product, qty };
      });
      const total = purchased.reduce((sum, item) => sum + item.price_pkr * item.qty, 0);
      const code = `NZ-${randomBytes(4).toString("hex").toUpperCase()}`;
      const inserted = database.prepare(`
        INSERT INTO orders (code, customer_name, phone, address, city, payment_method, total_pkr)
        VALUES (?, ?, ?, ?, ?, ?, ?)
      `).run(code, name, phone, address, city, paymentMethod, total);
      const addItem = database.prepare("INSERT INTO order_items (order_id, product_id, name, price_pkr, qty) VALUES (?, ?, ?, ?, ?)");
      const updateStock = database.prepare("UPDATE products SET stock = stock - ? WHERE id = ?");
      for (const item of purchased) {
        addItem.run(inserted.lastInsertRowid, item.id, item.name, item.price_pkr, item.qty);
        updateStock.run(item.qty, item.id);
      }
      database.exec("COMMIT");
      sendJson(response, 201, { code, status: "New", total_pkr: total, created_at: new Date().toISOString() });
    } catch (error) {
      database.exec("ROLLBACK");
      throw error;
    }
    return;
  }

  const trackMatch = route.match(/^\/api\/orders\/([^/]+)$/);
  if (method === "GET" && trackMatch) {
    const order = database.prepare("SELECT * FROM orders WHERE code = ?").get(trackMatch[1].toUpperCase());
    const phone = (url.searchParams.get("phone") || "").replace(/\D/g, "").slice(-10);
    if (!order || phone !== order.phone.replace(/\D/g, "").slice(-10)) throw new HttpError(404, "Order not found.");
    const items = database.prepare("SELECT name, price_pkr, qty FROM order_items WHERE order_id = ?").all(order.id);
    sendJson(response, 200, { code: order.code, status: order.status, total_pkr: order.total_pkr, created_at: order.created_at, items });
    return;
  }

  if (method === "POST" && route === "/api/admin/login") {
    const ip = checkLoginLimit(request);
    const body = await readJson(request);
    if (typeof body.email !== "string" || typeof body.password !== "string" || !verifyLogin(body.email, body.password)) {
      recordLoginFailure(ip);
      throw new HttpError(401, "Wrong email or password.");
    }
    loginAttempts.delete(ip);
    const admin = database.prepare("SELECT id, email FROM admins WHERE email = ?").get(body.email.trim().toLowerCase());
    const token = randomBytes(32).toString("hex");
    sessions.set(token, { adminId: admin.id, expiresAt: Date.now() + sessionLifetime });
    sendJson(response, 200, { token, email: admin.email });
    return;
  }

  const adminRoute = route.startsWith("/api/admin/");
  if (adminRoute) requireAdmin(request);

  if (method === "GET" && route === "/api/admin/stats") {
    const stats = database.prepare(`
      SELECT
        (SELECT COUNT(*) FROM products) AS products,
        (SELECT COUNT(*) FROM orders) AS orders,
        (SELECT COUNT(*) FROM orders WHERE status = 'New') AS new_orders,
        COALESCE((SELECT SUM(total_pkr) FROM orders WHERE status != 'Cancelled'), 0) AS revenue_pkr
    `).get();
    sendJson(response, 200, stats);
    return;
  }

  if (method === "GET" && route === "/api/admin/products") {
    sendJson(response, 200, database.prepare("SELECT * FROM products ORDER BY id").all().map(asProduct));
    return;
  }

  if (method === "POST" && route === "/api/admin/products") {
    const product = productFromRequest(await readJson(request));
    const result = insertProduct(product);
    const created = asProduct(database.prepare("SELECT * FROM products WHERE id = ?").get(result.lastInsertRowid));
    sendJson(response, 201, created);
    return;
  }

  const adminProductMatch = route.match(/^\/api\/admin\/products\/(\d+)$/);
  if (adminProductMatch) {
    const id = Number(adminProductMatch[1]);
    if (method === "PATCH") {
      const product = productFromRequest(await readJson(request), true);
      if (!updateProduct(id, product).changes) throw new HttpError(404, "Product not found.");
      sendJson(response, 200, asProduct(database.prepare("SELECT * FROM products WHERE id = ?").get(id)));
      return;
    }
    if (method === "DELETE") {
      if (!database.prepare("DELETE FROM products WHERE id = ?").run(id).changes) throw new HttpError(404, "Product not found.");
      response.writeHead(204).end();
      return;
    }
  }

  if (method === "GET" && route === "/api/admin/orders") {
    const status = url.searchParams.get("status");
    if (status && !statuses.includes(status)) throw new HttpError(400, "Unknown order status.");
    sendJson(response, 200, listOrders(status));
    return;
  }

  const statusMatch = route.match(/^\/api\/admin\/orders\/(\d+)\/status$/);
  if (method === "PATCH" && statusMatch) {
    const body = await readJson(request);
    if (!statuses.includes(body.status)) throw new HttpError(400, "Unknown order status.");
    const id = Number(statusMatch[1]);
    database.exec("BEGIN IMMEDIATE");
    try {
      const current = database.prepare("SELECT status FROM orders WHERE id = ?").get(id);
      if (!current) throw new HttpError(404, "Order not found.");
      if (current.status === "Cancelled" && body.status !== "Cancelled") {
        throw new HttpError(409, "A cancelled order cannot be reopened.");
      }
      if (body.status === "Cancelled" && current.status !== "Cancelled") {
        const items = database.prepare("SELECT product_id, qty FROM order_items WHERE order_id = ?").all(id);
        const restoreStock = database.prepare("UPDATE products SET stock = stock + ? WHERE id = ?");
        for (const item of items) {
          if (item.product_id !== null) restoreStock.run(item.qty, item.product_id);
        }
      }
      database.prepare("UPDATE orders SET status = ? WHERE id = ?").run(body.status, id);
      database.exec("COMMIT");
      sendJson(response, 200, database.prepare("SELECT * FROM orders WHERE id = ?").get(id));
    } catch (error) {
      database.exec("ROLLBACK");
      throw error;
    }
    return;
  }

  throw new HttpError(404, "Not found.");
}

const server = http.createServer(async (request, response) => {
  const url = new URL(request.url, `http://${host}:${port}`);
  try {
    if (url.pathname.startsWith("/api/")) {
      await handleApi(request, response, url);
      return;
    }

    const asset = files.get(url.pathname);
    if (request.method !== "GET" || !asset) {
      response.writeHead(404, { "Content-Type": "text/plain; charset=utf-8" });
      response.end("Not found");
      return;
    }

    const content = await readFile(path.join(__dirname, asset[0]));
    response.writeHead(200, {
      "Content-Type": asset[1],
      "Cache-Control": "no-store",
      "X-Content-Type-Options": "nosniff"
    });
    response.end(content);
  } catch (error) {
    if (error instanceof HttpError) {
      sendJson(response, error.status, { error: error.message });
      return;
    }
    console.error("Request failed:", error);
    sendJson(response, 500, { error: "Something went wrong. Please try again." });
  }
});

server.listen(port, host, () => {
  console.log(`niza.shoppping is ready at http://${host}:${port}`);
});

server.on("error", (error) => {
  console.error("Could not start niza.shoppping:", error);
  process.exitCode = 1;
});
