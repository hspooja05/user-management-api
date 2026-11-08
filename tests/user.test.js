
const request = require("supertest");
const jwt = require("jsonwebtoken");
const app = require("../src/app");
const prisma = require("../src/db");

const SECRET = process.env.JWT_SECRET || "user-management-secret";
const token = jwt.sign({ id: 1 }, SECRET);

let userId;
const email = `jest-${Date.now()}@example.com`;

beforeAll(async () => {
  await prisma.user.deleteMany({
    where: { email: { startsWith: "jest-" } },
  });
});

afterAll(async () => {
  await prisma.user.deleteMany({
    where: { email: { startsWith: "jest-" } },
  });
  await prisma.$disconnect();
});

describe("User Management API", () => {

  // HOME
  test("GET / should return API running message", async () => {
    const res = await request(app).get("/");

    expect(res.statusCode).toBe(200);
    expect(res.body.message).toBe("User Management API is running");
  });

  // CREATE USER
  test("POST /users should create a user", async () => {
    const res = await request(app).post("/users").send({
      name: "Test User",
      email,
      password: "password123",
    });

    expect(res.statusCode).toBe(201);
    expect(res.body.user.email).toBe(email);
    expect(res.body.user).not.toHaveProperty("password");

    userId = res.body.user.id;
  });

  test("POST /users should reject missing fields", async () => {
    const res = await request(app).post("/users").send({
      name: "Test User",
    });

    expect(res.statusCode).toBe(400);
  });

  test("POST /users should reject invalid email", async () => {
    const res = await request(app).post("/users").send({
      name: "Test User",
      email: "invalid-email",
      password: "password123",
    });

    expect(res.statusCode).toBe(400);
  });

  test("POST /users should reject short password", async () => {
    const res = await request(app).post("/users").send({
      name: "Test User",
      email: `short-${Date.now()}@example.com`,
      password: "123",
    });

    expect(res.statusCode).toBe(400);
  });

  test("POST /users should reject duplicate email", async () => {
    const res = await request(app).post("/users").send({
      name: "Another User",
      email,
      password: "password123",
    });

    expect(res.statusCode).toBe(409);
  });

  // AUTHENTICATION
  test("GET /users should reject unauthorized requests", async () => {
    const res = await request(app).get("/users");

    expect(res.statusCode).toBe(401);
  });

  test("GET /users should reject invalid token", async () => {
    const res = await request(app)
      .get("/users")
      .set("Authorization", "Bearer invalid-token");

    expect(res.statusCode).toBe(401);
  });

  // READ USERS
  test("GET /users should return all users", async () => {
    const res = await request(app)
      .get("/users")
      .set("Authorization", `Bearer ${token}`);

    expect(res.statusCode).toBe(200);
    expect(Array.isArray(res.body)).toBe(true);
  });

  test("GET /users/:id should return a user", async () => {
    const res = await request(app)
      .get(`/users/${userId}`)
      .set("Authorization", `Bearer ${token}`);

    expect(res.statusCode).toBe(200);
    expect(res.body.email).toBe(email);
  });

  test("GET /users/:id should reject invalid ID", async () => {
    const res = await request(app)
      .get("/users/abc")
      .set("Authorization", `Bearer ${token}`);

    expect(res.statusCode).toBe(400);
  });

  test("GET /users/:id should return 404 for missing user", async () => {
    const res = await request(app)
      .get("/users/99999999")
      .set("Authorization", `Bearer ${token}`);

    expect(res.statusCode).toBe(404);
  });

  // UPDATE USER
  test("PUT /users/:id should update a user", async () => {
    const res = await request(app)
      .put(`/users/${userId}`)
      .set("Authorization", `Bearer ${token}`)
      .send({ name: "Updated User" });

    expect(res.statusCode).toBe(200);
    expect(res.body.user.name).toBe("Updated User");
  });

  test("PUT /users/:id should reject empty update", async () => {
    const res = await request(app)
      .put(`/users/${userId}`)
      .set("Authorization", `Bearer ${token}`)
      .send({});

    expect(res.statusCode).toBe(400);
  });

  test("PUT /users/:id should return 404 for missing user", async () => {
    const res = await request(app)
      .put("/users/99999999")
      .set("Authorization", `Bearer ${token}`)
      .send({ name: "Updated User" });

    expect(res.statusCode).toBe(404);
  });

  test("PUT /users/:id should reject invalid ID", async () => {
    const res = await request(app)
      .put("/users/abc")
      .set("Authorization", `Bearer ${token}`)
      .send({ name: "Updated User" });

    expect(res.statusCode).toBe(400);
  });

  // DELETE USER
  test("DELETE /users/:id should delete a user", async () => {
    const res = await request(app)
      .delete(`/users/${userId}`)
      .set("Authorization", `Bearer ${token}`);

    expect(res.statusCode).toBe(200);
    expect(res.body.message).toBe("User deleted successfully");
  });

  test("DELETE /users/:id should return 404 for missing user", async () => {
    const res = await request(app)
      .delete("/users/99999999")
      .set("Authorization", `Bearer ${token}`);

    expect(res.statusCode).toBe(404);
  });

  test("DELETE /users/:id should reject invalid ID", async () => {
    const res = await request(app)
      .delete("/users/abc")
      .set("Authorization", `Bearer ${token}`);

    expect(res.statusCode).toBe(400);
  });

});
