import express from "express";
import mongoose from "mongoose";
import dotenv from "dotenv";
import cors from "cors";
import cookieParser from "cookie-parser";
import path from "path";
import { fileURLToPath } from "url";
import authRoutes from "./routes/authRoutes.js";
import fileRoutes from "./routes/fileRoutes.js";
import categoryRoutes from "./routes/categoryRoutes.js";
import linkRoutes from "./routes/linkRoutes.js";
import { formatBytes } from "./utils/format.js";

// Shared constants
const DEFAULT_LINK_LIMIT = 50;

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

dotenv.config();

const app = express();

// Global request logging - place right after app creation
app.use((req, res, next) => {
  console.log("=== GLOBAL REQUEST LOG ===");
  console.log(`${req.method} ${req.path} - ${new Date().toISOString()}`);
  console.log("All headers:", req.headers);
  next();
});

// Simple rate limiting middleware
const rateLimit = (windowMs = 15 * 60 * 1000, max = 100) => {
  // 15 minutes, 100 requests
  const requests = new Map();

  return (req, res, next) => {
    const ip = req.ip || req.connection.remoteAddress;
    const now = Date.now();
    const windowStart = now - windowMs;

    // Get existing requests for this IP
    const ipRequests = requests.get(ip) || [];

    // Filter out old requests
    const validRequests = ipRequests.filter((time) => time > windowStart);

    if (validRequests.length >= max) {
      return res.status(429).json({
        message: "Too many requests, please try again later",
        retryAfter: Math.ceil((validRequests[0] + windowMs - now) / 1000),
      });
    }

    // Add current request
    validRequests.push(now);
    requests.set(ip, validRequests);

    // Clean up old entries periodically
    if (Math.random() < 0.01) {
      // 1% chance to cleanup
      for (const [key, times] of requests.entries()) {
        if (times.length === 0 || times[0] < windowStart) {
          requests.delete(key);
        }
      }
    }

    next();
  };
};

app.use(
  cors({
    origin: process.env.CLIENT_URL || "http://localhost:4321",
    methods: ["GET", "POST", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
    credentials: true,
  }),
);

// Debug middleware - place right after CORS to catch all requests
app.use((req, res, next) => {
  console.log("=== EARLY REQUEST DEBUG ===");
  console.log(`${req.method} ${req.path}`);
  console.log("Headers:", JSON.stringify(req.headers, null, 2));
  console.log("Query:", req.query);
  next();
});
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// Debug middleware to track all requests
app.use((req, res, next) => {
  console.log("=== REQUEST DEBUG ===");
  console.log(`${req.method} ${req.path} - Content-Type: ${req.headers['content-type'] || 'none'}`);
  console.log("Request body keys:", req.body ? Object.keys(req.body) : 'no body yet');
  next();
});

// Set EJS as view engine
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

// Serve static files from public directory
app.use(express.static(path.join(__dirname, "public")));

// Apply rate limiting to all routes (except login for debugging)
app.use((req, res, next) => {
  if (req.path === '/login' && req.method === 'POST') {
    console.log("=== LOGIN REQUEST BYPASSING RATE LIMIT ===");
    return next();
  }
  return rateLimit()(req, res, next);
});

// Health check endpoint (must be very first route)
app.get("/health", (req, res) => {
  res.json({
    status: "OK",
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    version: process.env.npm_package_version || "1.0.0",
  });
});

// Configuration endpoint (public - no authentication required)
app.get("/api/config", (req, res) => {
  // Return only safe, public configuration values
  res.json({
    maxFileSize: parseInt(process.env.MAX_FILE_SIZE) || 100 * 1024 * 1024, // Default 100MB in bytes
    maxFileSizeFormatted: formatBytes(parseInt(process.env.MAX_FILE_SIZE) || 100 * 1024 * 1024),
    maxFilesPerUpload: 10, // This matches the Multer configuration in fileRoutes.js
    supportedFileTypes: "All file types supported", // Updated to reflect any file type support
    serverTime: new Date().toISOString(),
  });
});

// Authentication middleware for protected routes
const requireAuth = async (req, res, next) => {
  console.log("=== REQUIREAUTH MIDDLEWARE DEBUG ===");
  console.log("Request path:", req.path);
  console.log("Available cookies:", req.cookies ? Object.keys(req.cookies) : 'none');
  console.log("Authorization header:", req.headers.authorization || 'not present');
  console.log("Query token:", req.query.token || 'not present');

  const authHeader = req.headers.authorization;
  const headerToken = authHeader && authHeader.startsWith("Bearer ") ? authHeader.split(" ")[1] : null;
  const token =
    req.cookies?.token ||
    headerToken ||
    req.query.token;

  console.log("Token found:", token ? 'YES' : 'NO');
  console.log("Token source:", token === req.cookies?.token ? 'cookie' :
                               token === headerToken ? 'header' : 'query');

  if (!token) {
    console.log("No token found, redirecting to login");
    return res.redirect("/login");
  }

  try {
    const jwt = await import("jsonwebtoken");
    const decoded = jwt.default.verify(token, process.env.JWT_SECRET);
    console.log("Token verified successfully for user:", decoded.user?.username);
    req.user = decoded;
    next();
  } catch (error) {
    console.error("Token verification failed:", error.message);
    return res.redirect("/login");
  }
};

// Home page route
app.get("/", async (req, res) => {
  try {
    console.log("=== HOME PAGE ROUTE DEBUG ===");
    console.log("Request URL:", req.url);
    console.log("Request query:", req.query);

    // Parse query parameters
    const activeTab = req.query.tab || "files";
    const searchTerm = req.query.search || "";
    const sortBy = req.query.sort || "uploadedAt";
    const sortOrder = req.query.order || "desc";
    const currentPage = parseInt(req.query.page) || 1;

    console.log("Parsed parameters:", {
      activeTab,
      searchTerm,
      sortBy,
      sortOrder,
      currentPage
    });

    // Fetch data from APIs
    console.log("Fetching data from APIs...");
    const [filesResponse, linksResponse, categoriesResponse] =
      await Promise.all([
        fetch(`${req.protocol}://${req.get("host")}/api/files`),
        fetch(`${req.protocol}://${req.get("host")}/api/links?isActive=true&limit=${DEFAULT_LINK_LIMIT}`),
        fetch(`${req.protocol}://${req.get("host")}/api/categories/public`),
      ]);

    console.log("API responses received:", {
      filesStatus: filesResponse.status,
      linksStatus: linksResponse.status,
      categoriesStatus: categoriesResponse.status
    });

    const files = await filesResponse.json();
    const linksData = await linksResponse.json();
    const categories = await categoriesResponse.json();

    console.log("API data parsed:", {
      filesType: typeof files,
      filesIsArray: Array.isArray(files),
      filesLength: files?.length || 0,
      linksDataType: typeof linksData,
      linksDataKeys: linksData ? Object.keys(linksData) : 'null',
      categoriesType: typeof categories,
      categoriesIsArray: Array.isArray(categories),
      categoriesLength: categories?.length || 0
    });

    const links = linksData.links || [];

    console.log("Processed data:", {
      filesType: typeof files,
      linksType: typeof links,
      linksIsArray: Array.isArray(links),
      linksLength: links?.length || 0,
      categoriesType: typeof categories
    });

    // Files are already filtered in the API (exclude URL-type files) - displaySize is handled by the API

    console.log("Data before rendering template:", {
      filesType: typeof files,
      filesIsArray: Array.isArray(files),
      filesLength: files?.length || 0,
      linksType: typeof links,
      linksIsArray: Array.isArray(links),
      linksLength: links?.length || 0,
      categoriesType: typeof categories,
      categoriesIsArray: Array.isArray(categories),
      categoriesLength: categories?.length || 0
    });

    // Check for Promise objects in data
    const dataToRender = {
      files: files,
      links: links,
      categories: categories,
      activeTab: activeTab,
      searchTerm: searchTerm,
      sortBy: sortBy,
      sortOrder: sortOrder,
      currentPage: currentPage,
      linkCurrentPage: currentPage,
      linkSearchTerm: searchTerm,
      linkSortBy: sortBy,
      linkSortOrder: sortOrder,
      error: null,
      loading: false,
      user: req.user || null,
    };

    console.log("Checking for Promise objects in template data...");
    for (const [key, value] of Object.entries(dataToRender)) {
      if (value && typeof value === 'object' && typeof value.then === 'function') {
        console.error(`ERROR: Promise object found in template data for key '${key}':`, value);
      } else {
        console.log(`✓ ${key}: ${typeof value} ${Array.isArray(value) ? `[${value.length}]` : ''}`);
      }
    }

    console.log("Rendering template with data...");
    const renderedBody = await renderEjsContent("pages/index", dataToRender);

    res.render("layout", {
      title: "File Server",
      body: renderedBody,
    });
  } catch (error) {
    console.error("=== ERROR RENDERING HOME PAGE ===");
    console.error("Error details:", error);
    console.error("Error stack:", error.stack);

    // Check if error is related to Promise objects
    if (error.message && error.message.includes('Promise')) {
      console.error("Promise-related error detected!");
    }

    const errorData = {
      files: [],
      links: [],
      categories: [],
      activeTab: "files",
      searchTerm: "",
      sortBy: "uploadedAt",
      sortOrder: "desc",
      currentPage: 1,
      linkCurrentPage: 1,
      linkSearchTerm: "",
      linkSortBy: "uploadedAt",
      linkSortOrder: "desc",
      error: "Error loading content. Please try again.",
      loading: false,
      user: req.user || null,
    };

    // Error fallback files - displaySize is now handled by the API

    console.log("Error fallback data:", {
      filesType: typeof errorData.files,
      linksType: typeof errorData.links,
      categoriesType: typeof errorData.categories
    });

    const errorBody = await renderEjsContent("pages/index", errorData);

    res.render("layout", {
      title: "File Server",
      body: errorBody,
    });
  }
});

// Login page route (GET)
app.get("/login", async (req, res) => {
  // Redirect if already logged in
  const authHeader = req.headers.authorization;
  const token = (authHeader && authHeader.startsWith("Bearer "))
    ? authHeader.split(" ")[1]
    : req.query.token;

  if (token) {
    try {
      const jwt = await import("jsonwebtoken");
      jwt.default.verify(token, process.env.JWT_SECRET);
      return res.redirect("/admin");
    } catch (error) {
      // Token invalid, continue to login page
    }
  }

  console.log("Rendering login page...");
  const loginBody = await renderEjsContent("pages/login", {
    error: null,
    user: null,
  });

  res.render("layout", {
    title: "Login - File Server",
    body: loginBody,
  });
});

// Login form submission route (POST)
app.post("/login", express.urlencoded({ extended: true }), (req, res, next) => {
  console.log("=== LOGIN ROUTE MIDDLEWARE DEBUG ===");
  console.log("Raw body:", req.body);
  console.log("Content-Type:", req.headers['content-type']);
  next();
}, async (req, res) => {
  try {
    console.log("=== LOGIN POST ROUTE REACHED ===");
    console.log("Request method:", req.method);
    console.log("Request path:", req.path);
    console.log("Request body raw:", req.body);
    console.log("=== LOGIN POST REQUEST DEBUG ===");
    console.log("Request body keys:", Object.keys(req.body));
    console.log("Request body:", {
      username: req.body.username ? '[PRESENT]' : '[MISSING]',
      password: req.body.password ? '[PRESENT]' : '[MISSING]',
      allFields: req.body
    });

    const { username, password } = req.body;

    // Validate input
    console.log("Validating login input...");
    console.log("Username:", username ? `"${username}"` : 'undefined/null');
    console.log("Password:", password ? '[PRESENT]' : 'undefined/null');

    if (!username || !password) {
      console.error("LOGIN VALIDATION FAILED: Missing username or password");
      console.log("Sending validation error response");
      const errorBody = await renderEjsContent("pages/login", {
        error: "Please provide both username and password",
        user: null,
      });
      return res.render("layout", {
        title: "Login - File Server",
        body: errorBody,
      });
    }

    console.log("✓ Input validation passed");

    // Use the existing auth API
    console.log("Calling auth API...");
    const response = await fetch(
      `${req.protocol}://${req.get("host")}/api/auth/login`,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ username, password }),
      },
    );

    console.log("Auth API response status:", response.status);
    const data = await response.json();
    console.log("Auth API response data:", {
      ok: response.ok,
      hasToken: !!data.token,
      message: data.message || 'No message',
      dataKeys: Object.keys(data)
    });

    if (response.ok && data.token) {
       console.log("✓ Login successful, setting cookie and redirecting");
       // Set token in cookie for server-side use
       res.cookie("token", data.token, {
         httpOnly: true,
         secure: process.env.NODE_ENV === "production",
         sameSite: "strict",
         maxAge: 24 * 60 * 60 * 1000, // 24 hours
       });

       console.log("Cookie set successfully:", {
         name: "token",
         httpOnly: true,
         secure: process.env.NODE_ENV === "production",
         sameSite: "strict",
         maxAge: 24 * 60 * 60 * 1000
       });

       // Redirect to admin panel with token in URL for frontend to capture
       res.redirect(`/admin?token=${data.token}`);
    } else {
      console.log("✗ Login failed:", data.message || "Invalid credentials");
      // Login failed
      res.render("layout", {
        title: "Login - File Server",
        body: await renderEjsContent("pages/login", {
          error: data.message || "Invalid username or password",
          user: null,
        }),
      });
    }
  } catch (error) {
    console.error("Login error:", error);
    res.render("layout", {
      title: "Login - File Server",
      body: await renderEjsContent("pages/login", {
        error: "An error occurred during login. Please try again.",
        user: null,
      }),
    });
  }
});

// Admin page route (protected)
app.get("/admin", requireAuth, async (req, res) => {
  try {
    console.log("=== ADMIN PAGE ROUTE DEBUG ===");
    console.log("User authenticated:", req.user?.user?.username || 'unknown');

    // Get token from the same sources as requireAuth middleware
    const authHeader = req.headers.authorization;
    const token =
      req.cookies?.token ||
      (authHeader && authHeader.startsWith("Bearer ") ? authHeader.split(" ")[1] : null) ||
      req.query.token;

    console.log("Token available for API calls:", token ? 'YES' : 'NO');

    if (!token) {
      console.error("No token available for admin API calls");
      return res.redirect("/login");
    }

    // Fetch data for admin panel
    console.log("Fetching admin data from APIs...");
    const [categoriesResponse, filesResponse, linksResponse] = await Promise.all([
      fetch(`${req.protocol}://${req.get("host")}/api/categories`, {
        headers: {
          Authorization: `Bearer ${token}`,
        },
      }),
      fetch(`${req.protocol}://${req.get("host")}/api/files`, {
        headers: {
          Authorization: `Bearer ${token}`,
        },
      }),
      fetch(`${req.protocol}://${req.get("host")}/api/links?isActive=true&limit=${DEFAULT_LINK_LIMIT}`, {
        headers: {
          Authorization: `Bearer ${token}`,
        },
      }),
    ]);

    console.log("Admin API responses:", {
      categoriesStatus: categoriesResponse.status,
      filesStatus: filesResponse.status,
      linksStatus: linksResponse.status
    });

    const categories = await categoriesResponse.json();
    const files = await filesResponse.json();
    const linksData = await linksResponse.json();

    // Use only active links
    const links = linksData.links || [];

    console.log("Admin data loaded:", {
      categoriesType: typeof categories,
      categoriesLength: categories?.length || 0,
      filesType: typeof files,
      filesLength: files?.length || 0
    });

    res.render("layout", {
      title: "Admin Panel - File Server",
      body: await renderEjsContent("pages/admin", {
        categories: categories,
        files: files,
        links: links,
        user: req.user,
      }),
    });
  } catch (error) {
    console.error("Error rendering admin page:", error);
    console.error("Error stack:", error.stack);
    res.redirect("/login");
  }
});


// Redirect old admin-links route to unified admin panel
app.get("/admin-links", requireAuth, (req, res) => {
  res.redirect("/admin?tab=links");
});

// Logout route
app.get("/logout", (req, res) => {
  res.redirect("/login");
});

// Helper function to render EJS file content
async function renderEjsContent(templatePath, data) {
  try {
    console.log(`=== RENDERING EJS TEMPLATE: ${templatePath} ===`);
    console.log("Template data types:", {
      dataType: typeof data,
      dataKeys: data ? Object.keys(data) : 'null',
      filesType: typeof data?.files,
      filesIsArray: Array.isArray(data?.files),
      filesLength: data?.files?.length || 0,
      linksType: typeof data?.links,
      linksIsArray: Array.isArray(data?.links),
      linksLength: data?.links?.length || 0,
      categoriesType: typeof data?.categories,
      categoriesIsArray: Array.isArray(data?.categories),
      categoriesLength: data?.categories?.length || 0
    });

    // Check for Promise objects in data before rendering
    if (data) {
      for (const [key, value] of Object.entries(data)) {
        if (value && typeof value === 'object' && typeof value.then === 'function') {
          console.error(`ERROR: Promise object found in template data for key '${key}' in renderEjsContent:`, value);
        }
      }
    }

    const ejs = await import("ejs");
    const fs = await import("fs");
    const pathModule = await import("path");

    const template = fs.readFileSync(
      pathModule.default.join(__dirname, "views", templatePath + ".ejs"),
      "utf8",
    );

    console.log(`Template loaded successfully, length: ${template.length} characters`);
    const rendered = ejs.render(template, data);
    console.log(`Template rendered successfully, output length: ${rendered.length} characters`);

    return rendered;
  } catch (error) {
    console.error(`Error rendering ${templatePath}:`, error);
    return `<div>Error loading template: ${templatePath}</div>`;
  }
}

// Allow direct downloads from uploads directory
app.use(
  "/downloads",
  express.static("uploads", {
    setHeaders: (res, path) => {
      const filename = path.split("/").pop();
      if (filename) {
        res.set(
          "Content-Disposition",
          `attachment; filename=${encodeURIComponent(filename)}`,
        );
      }
    },
  }),
);

// Request logging middleware
app.use((req, res, next) => {
  const start = Date.now();
  res.on("finish", () => {
    const duration = Date.now() - start;
    console.log(`${req.method} ${req.path} ${res.statusCode} - ${duration}ms`);
  });
  next();
});

// Global error handling middleware
app.use((err, req, res, next) => {
  console.error("Unhandled error:", {
    error: err.message,
    stack: err.stack,
    url: req.url,
    method: req.method,
    ip: req.ip,
    timestamp: new Date().toISOString(),
  });
  res.status(500).json({
    message: "Internal server error",
    ...(process.env.NODE_ENV === "development" && { error: err.message }),
  });
});

// MongoDB connection with retry logic
const connectDB = async (retries = 3) => {
  for (let i = 0; i < retries; i++) {
    try {
      await mongoose.connect(process.env.MONGO_URL);
      console.log("MongoDB Connected");
      return;
    } catch (err) {
      console.error(`MongoDB connection attempt ${i + 1} failed:`, err.message);
      if (i < retries - 1) {
        console.log(`Retrying in ${i + 1} seconds...`);
        await new Promise((resolve) => setTimeout(resolve, (i + 1) * 1000));
      }
    }
  }
  console.error("Failed to connect to MongoDB after multiple attempts");
  process.exit(1);
};

connectDB();

// Schedule periodic cleanup of orphaned files (every 24 hours)
setInterval(
  async () => {
    try {
      console.log("Running scheduled cleanup of orphaned files...");
      const { cleanupOrphanedFiles } = await import("./routes/fileRoutes.js");
      const deletedCount = await cleanupOrphanedFiles();
      if (deletedCount > 0) {
        console.log(`Scheduled cleanup removed ${deletedCount} orphaned files`);
      }
    } catch (error) {
      console.error("Scheduled cleanup failed:", error);
    }
  },
  24 * 60 * 60 * 1000,
); // 24 hours

// Ensure uploads directory exists
const uploadsDir = path.join(process.cwd(), "uploads");
import("fs").then((fs) => {
  if (!fs.existsSync(uploadsDir)) {
    fs.mkdirSync(uploadsDir, { recursive: true });
    console.log("Created uploads directory");
  }
});

// Graceful shutdown handling
process.on("SIGTERM", async () => {
  console.log("SIGTERM received, shutting down gracefully");
  process.exit(0);
});

process.on("SIGINT", async () => {
  console.log("SIGINT received, shutting down gracefully");
  process.exit(0);
});

app.use("/api/auth", authRoutes);
app.use("/api/files", fileRoutes);
app.use("/api/categories", categoryRoutes);
app.use("/api/links", linkRoutes);

// 404 handler for unmatched routes
app.use((req, res) => {
  res.status(404).json({ message: "Route not found" });
});

const PORT = process.env.PORT || 5000;
const server = app.listen(PORT, () =>
  console.log(`Server running on port ${PORT} in ${process.env.NODE_ENV || 'development'} mode`),
);

// Export for Render
export default app;

// Graceful shutdown
process.on("SIGTERM", () => {
  console.log("SIGTERM received, shutting down gracefully");
  server.close(() => {
    console.log("Process terminated");
  });
});

process.on("SIGINT", () => {
  console.log("SIGINT received, shutting down gracefully");
  server.close(() => {
    console.log("Process terminated");
  });
});
