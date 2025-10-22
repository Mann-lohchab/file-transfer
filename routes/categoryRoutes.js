import express from "express";
import Category from "../models/Category.js";
import File from "../models/File.js";
import { protect } from "../middleware/authMiddleware.js";

const router = express.Router();

// Get all categories (admin only)
router.get("/", protect, async (req, res) => {
  try {
    const categories = await Category.find({}).sort({ createdAt: 1 });
    res.json(categories);
  } catch (error) {
    res.status(500).json({ message: error.message || 'Error fetching categories' });
  }
});

// Get all categories (public)
router.get("/public", async (req, res) => {
  try {
    const categories = await Category.find({}).sort({ createdAt: 1 });

    console.log("=== CATEGORIES API DEBUG ===");
    console.log("Categories data:", {
      categoriesType: typeof categories,
      categoriesIsArray: Array.isArray(categories),
      categoriesLength: categories?.length || 0,
      firstCategoryType: categories?.[0] ? typeof categories[0] : 'no categories'
    });

    res.json(categories);
  } catch (error) {
    console.error("Categories API error:", error);
    res.status(500).json({ message: error.message || 'Error fetching categories' });
  }
});

// Create new category
router.post("/", protect, async (req, res) => {
  try {
    const { name, description } = req.body;
    if (!name) {
      return res.status(400).json({ message: 'Name is required' });
    }

    const existingCategory = await Category.findOne({ name });
    if (existingCategory) {
      return res.status(400).json({ message: 'Category name must be unique' });
    }

    const category = new Category({
      name,
      description: description || ''
    });

    await category.save();
    res.status(201).json(category);
  } catch (error) {
    res.status(500).json({ message: error.message || 'Error creating category' });
  }
});

// Update category
router.put("/:id", protect, async (req, res) => {
  try {
    const { name, description } = req.body;
    if (!name) {
      return res.status(400).json({ message: 'Name is required' });
    }

    const existingCategory = await Category.findOne({ name, _id: { $ne: req.params.id } });
    if (existingCategory) {
      return res.status(400).json({ message: 'Category name must be unique' });
    }

    const category = await Category.findByIdAndUpdate(
      req.params.id,
      { name, description: description || '' },
      { new: true, runValidators: true }
    );

    if (!category) {
      return res.status(404).json({ message: 'Category not found' });
    }

    // Update fileCount
    const fileCount = await File.countDocuments({ categoryId: category._id });
    category.fileCount = fileCount;
    await category.save();

    res.json(category);
  } catch (error) {
    res.status(500).json({ message: error.message || 'Error updating category' });
  }
});

// Delete category
router.delete("/:id", protect, async (req, res) => {
  try {
    const category = await Category.findById(req.params.id);
    if (!category) {
      return res.status(404).json({ message: 'Category not found' });
    }

    // Move files to uncategorized or delete if no files
    const fileCount = await File.countDocuments({ categoryId: category._id });
    if (fileCount > 0) {
      await File.updateMany({ categoryId: category._id }, { $set: { categoryId: null } });
    }

    await Category.findByIdAndDelete(req.params.id);
    res.json({ message: 'Category deleted successfully' });
  } catch (error) {
    res.status(500).json({ message: error.message || 'Error deleting category' });
  }
});

// Initialize default categories (call once or on startup if needed)
router.post("/initialize", protect, async (req, res) => {
  try {
    const defaultCategories = [
      { name: "DIET", description: "Diet related files and tools" },
      { name: "10.0.0.2", description: "10.0.0.2 specific files" },
      { name: "Registry", description: "Registry files and configurations" },
      { name: "UTILITY", description: "Utility tools and applications" }
    ];

    const createdCategories = [];
    for (const catData of defaultCategories) {
      const existing = await Category.findOne({ name: catData.name });
      if (!existing) {
        const category = new Category(catData);
        await category.save();
        createdCategories.push(category);
      }
    }

    res.json({ message: 'Default categories initialized', created: createdCategories });
  } catch (error) {
    res.status(500).json({ message: error.message || 'Error initializing categories' });
  }
});

export default router;