import express from 'express';
import Link from '../models/Link.js';
import Category from '../models/Category.js';
import { protect } from '../middleware/authMiddleware.js';

const router = express.Router();

// GET /api/links - Get all links with optional filtering (public for download page)
router.get('/', async (req, res) => {
  try {
    const {
      categoryId,
      platform,
      search,
      isActive = true,
      page = 1,
      limit = 50
    } = req.query;

    // Build filter object
    const filter = { isActive };

    if (categoryId) {
      filter.categoryId = categoryId;
    }

    if (platform) {
      filter.platform = platform;
    }

    if (search) {
      filter.$or = [
        { name: { $regex: search, $options: 'i' } },
        { description: { $regex: search, $options: 'i' } },
        { version: { $regex: search, $options: 'i' } }
      ];
    }

    const skip = (parseInt(page) - 1) * parseInt(limit);

    const links = await Link.find(filter)
      .populate('categoryId', 'name description')
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(parseInt(limit));

    const total = await Link.countDocuments(filter);

    const responseData = {
      links,
      pagination: {
        currentPage: parseInt(page),
        totalPages: Math.ceil(total / parseInt(limit)),
        totalLinks: total,
        hasNext: skip + links.length < total,
        hasPrev: parseInt(page) > 1
      }
    };

    console.log("=== LINKS API DEBUG ===");
    console.log("Filter:", filter);
    console.log("Response data:", {
      linksType: typeof responseData.links,
      linksIsArray: Array.isArray(responseData.links),
      linksLength: responseData.links?.length || 0,
      paginationType: typeof responseData.pagination,
      totalLinks: responseData.pagination?.totalLinks || 0
    });

    res.json(responseData);
  } catch (error) {
    console.error('Error fetching links:', error);
    res.status(500).json({ msg: 'Server error' });
  }
});

// GET /api/links/:id - Get single link by ID (public for download page)
router.get('/:id', async (req, res) => {
  try {
    const link = await Link.findById(req.params.id)
      .populate('categoryId', 'name description');

    if (!link) {
      return res.status(404).json({ msg: 'Link not found' });
    }

    res.json(link);
  } catch (error) {
    console.error('Error fetching link:', error);
    if (error.kind === 'ObjectId') {
      return res.status(400).json({ msg: 'Invalid link ID' });
    }
    res.status(500).json({ msg: 'Server error' });
  }
});

// POST /api/links - Create new link (admin only)
router.post('/', protect, async (req, res) => {
  try {
    const {
      name,
      version,
      description,
      downloadUrl,
      categoryId,
      tags = [],
      fileSize,
      platform = 'Universal'
    } = req.body;

    // Validate required fields
    if (!name || !version || !downloadUrl) {
      return res.status(400).json({
        msg: 'Name, version, and download URL are required'
      });
    }

    // Validate download URL format
    try {
      new URL(downloadUrl);
    } catch {
      return res.status(400).json({ msg: 'Invalid download URL format' });
    }

    // Check if category exists if provided
    if (categoryId) {
      const category = await Category.findById(categoryId);
      if (!category) {
        return res.status(400).json({ msg: 'Category not found' });
      }
    }

    const link = new Link({
      name,
      version,
      description,
      downloadUrl,
      categoryId,
      tags,
      fileSize,
      platform
    });

    const savedLink = await link.save();

    // Populate category info for response
    await savedLink.populate('categoryId', 'name description');

    res.status(201).json(savedLink);
  } catch (error) {
    console.error('Error creating link:', error);
    if (error.code === 11000) {
      return res.status(400).json({ msg: 'Link with similar details already exists' });
    }
    res.status(500).json({ msg: 'Server error' });
  }
});

// PUT /api/links/:id - Update link (admin only)
router.put('/:id', protect, async (req, res) => {
  try {
    const {
      name,
      version,
      description,
      downloadUrl,
      categoryId,
      tags,
      fileSize,
      platform,
      isActive
    } = req.body;

    const link = await Link.findById(req.params.id);
    if (!link) {
      return res.status(404).json({ msg: 'Link not found' });
    }

    // Validate download URL if provided
    if (downloadUrl) {
      try {
        new URL(downloadUrl);
      } catch {
        return res.status(400).json({ msg: 'Invalid download URL format' });
      }
    }

    // Check if category exists if provided
    if (categoryId) {
      const category = await Category.findById(categoryId);
      if (!category) {
        return res.status(400).json({ msg: 'Category not found' });
      }
    }

    // Update fields
    if (name) link.name = name;
    if (version) link.version = version;
    if (description !== undefined) link.description = description;
    if (downloadUrl) link.downloadUrl = downloadUrl;
    if (categoryId !== undefined) link.categoryId = categoryId;
    if (tags !== undefined) link.tags = tags;
    if (fileSize !== undefined) link.fileSize = fileSize;
    if (platform) link.platform = platform;
    if (isActive !== undefined) link.isActive = isActive;

    const updatedLink = await link.save();
    await updatedLink.populate('categoryId', 'name description');

    res.json(updatedLink);
  } catch (error) {
    console.error('Error updating link:', error);
    if (error.kind === 'ObjectId') {
      return res.status(400).json({ msg: 'Invalid link ID' });
    }
    res.status(500).json({ msg: 'Server error' });
  }
});

// DELETE /api/links/:id - Delete link (soft delete by setting isActive to false) (admin only)
router.delete('/:id', protect, async (req, res) => {
  try {
    const link = await Link.findById(req.params.id);
    if (!link) {
      return res.status(404).json({ msg: 'Link not found' });
    }

    link.isActive = false;
    await link.save();

    res.json({ msg: 'Link deleted successfully' });
  } catch (error) {
    console.error('Error deleting link:', error);
    if (error.kind === 'ObjectId') {
      return res.status(400).json({ msg: 'Invalid link ID' });
    }
    res.status(500).json({ msg: 'Server error' });
  }
});

// DELETE /api/links/:id/permanent - Permanently delete link from database (admin only)
router.delete('/:id/permanent', protect, async (req, res) => {
  try {
    const link = await Link.findById(req.params.id);
    if (!link) {
      return res.status(404).json({ msg: 'Link not found' });
    }

    await Link.findByIdAndDelete(req.params.id);

    res.json({ msg: 'Link permanently deleted' });
  } catch (error) {
    console.error('Error permanently deleting link:', error);
    if (error.kind === 'ObjectId') {
      return res.status(400).json({ msg: 'Invalid link ID' });
    }
    res.status(500).json({ msg: 'Server error' });
  }
});

// POST /api/links/:id/download - Increment download count (public for download page)
router.post('/:id/download', async (req, res) => {
  try {
    const link = await Link.findById(req.params.id);
    if (!link) {
      return res.status(404).json({ msg: 'Link not found' });
    }

    if (!link.isActive) {
      return res.status(404).json({ msg: 'Link not available' });
    }

    const updatedLink = await Link.findByIdAndUpdate(
      link._id,
      { $inc: { downloadCount: 1 } },
      { new: true }
    );

    res.json({
      msg: 'Download count updated',
      downloadCount: updatedLink.downloadCount,
      downloadUrl: updatedLink.downloadUrl
    });
  } catch (error) {
    console.error('Error updating download count:', error);
    if (error.kind === 'ObjectId') {
      return res.status(400).json({ msg: 'Invalid link ID' });
    }
    res.status(500).json({ msg: 'Server error' });
  }
});

// GET /api/links/stats/summary - Get links statistics (admin only)
router.get('/stats/summary', protect, async (req, res) => {
  try {
    const totalLinks = await Link.countDocuments({ isActive: true });
    const totalDownloads = await Link.aggregate([
      { $match: { isActive: true } },
      { $group: { _id: null, total: { $sum: '$downloadCount' } } }
    ]);

    const categoryStats = await Link.aggregate([
      { $match: { isActive: true } },
      {
        $group: {
          _id: '$categoryId',
          count: { $sum: 1 },
          totalDownloads: { $sum: '$downloadCount' }
        }
      }
    ]);

    const platformStats = await Link.aggregate([
      { $match: { isActive: true } },
      {
        $group: {
          _id: '$platform',
          count: { $sum: 1 }
        }
      }
    ]);

    res.json({
      totalLinks,
      totalDownloads: totalDownloads[0]?.total || 0,
      categoryStats,
      platformStats: platformStats.reduce((acc, stat) => {
        acc[stat._id] = stat.count;
        return acc;
      }, {})
    });
  } catch (error) {
    console.error('Error fetching link stats:', error);
    res.status(500).json({ msg: 'Server error' });
  }
});

export default router;