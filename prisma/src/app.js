
const express = require("express");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const { z } = require("zod");
const prisma = require("./db");

const app = express();
app.use(express.json());

const JWT_SECRET = process.env.JWT_SECRET || "user-management-secret";

function authenticate(req, res, next) {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({ message: "Unauthorized: Token required" });
  }

  try {
    req.user = jwt.verify(authHeader.split(" ")[1], JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ message: "Invalid or expired token" });
  }
}

const userSchema = z.object({
  name: z.string().min(2),
  email: z.email(),
  password: z.string().min(6),
});

app.get("/", (req, res) => {
  res.json({ message: "User Management API is running" });
});

// CREATE USER
app.post("/users", async (req, res) => {
  try {
    const result = userSchema.safeParse(req.body);

    if (!result.success) {
      return res.status(400).json({
        message: "Validation failed",
        errors: result.error.issues,
      });
    }

    const { name, email, password } = result.data;

    const existingUser = await prisma.user.findUnique({
      where: { email },
    });

    if (existingUser) {
      return res.status(409).json({ message: "Email already exists" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const user = await prisma.user.create({
      data: { name, email, password: hashedPassword },
      select: {
        id: true,
        name: true,
        email: true,
        createdAt: true,
      },
    });

    res.status(201).json({ message: "User created", user });
  } catch (error) {
    res.status(500).json({ message: "Server error" });
  }
});

// READ ALL USERS
app.get("/users", authenticate, async (req, res) => {
  try {
    const users = await prisma.user.findMany({
      select: { id: true, name: true, email: true, createdAt: true },
    });
    res.json(users);
  } catch {
    res.status(500).json({ message: "Server error" });
  }
});

// READ SINGLE USER
app.get("/users/:id", authenticate, async (req, res) => {
  try {
    const id = Number(req.params.id);

    if (!Number.isInteger(id) || id <= 0) {
      return res.status(400).json({ message: "Invalid user ID" });
    }

    const user = await prisma.user.findUnique({
      where: { id },
      select: { id: true, name: true, email: true, createdAt: true },
    });

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    res.json(user);
  } catch {
    res.status(500).json({ message: "Server error" });
  }
});

// UPDATE USER
app.put("/users/:id", authenticate, async (req, res) => {
  try {
    const id = Number(req.params.id);

    if (!Number.isInteger(id) || id <= 0) {
      return res.status(400).json({ message: "Invalid user ID" });
    }

    const updateSchema = z.object({
      name: z.string().min(2).optional(),
      email: z.email().optional(),
      password: z.string().min(6).optional(),
    }).refine(data => Object.keys(data).length > 0);

    const result = updateSchema.safeParse(req.body);

    if (!result.success) {
      return res.status(400).json({ message: "Invalid update data" });
    }

    const existing = await prisma.user.findUnique({ where: { id } });

    if (!existing) {
      return res.status(404).json({ message: "User not found" });
    }

    const data = { ...result.data };

    if (data.password) {
      data.password = await bcrypt.hash(data.password, 10);
    }

    const user = await prisma.user.update({
      where: { id },
      data,
      select: { id: true, name: true, email: true, createdAt: true },
    });

    res.json({ message: "User updated", user });
  } catch (error) {
    if (error.code === "P2002") {
      return res.status(409).json({ message: "Email already exists" });
    }
    res.status(500).json({ message: "Server error" });
  }
});

// DELETE USER
app.delete("/users/:id", authenticate, async (req, res) => {
  try {
    const id = Number(req.params.id);

    if (!Number.isInteger(id) || id <= 0) {
      return res.status(400).json({ message: "Invalid user ID" });
    }

    const existing = await prisma.user.findUnique({ where: { id } });

    if (!existing) {
      return res.status(404).json({ message: "User not found" });
    }

    await prisma.user.delete({ where: { id } });

    res.json({ message: "User deleted successfully" });
  } catch {
    res.status(500).json({ message: "Server error" });
  }
});

module.exports = app;
