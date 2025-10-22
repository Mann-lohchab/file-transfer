import express from "express";
import multer from "multer";
import { promises as fsPromises } from 'fs';
import fs from 'fs';
import path from "path";
import File from "../models/File.js";
import Category from "../models/Category.js";
import mongoose from "mongoose";
import { protect } from "../middleware/authMiddleware.js";
import { formatBytes } from "../utils/format.js";

// Utility function to clean up orphaned files in uploads directory
const cleanupOrphanedFiles = async () => {
  try {
    console.log('Starting cleanup of orphaned files in uploads directory...');

    // Get all files from uploads directory
    const uploadDir = path.join(process.cwd(), 'uploads');
    let uploadedFiles = [];
    try {
      uploadedFiles = await fsPromises.readdir(uploadDir);
    } catch (error) {
      console.log('Uploads directory does not exist or is empty');
      return 0;
    }

    // Get all file records from database (only actual files, not URLs)
    const dbFiles = await File.find({ type: 'file' }, 'path filename');

    // Create set of files that should exist
    const expectedFiles = new Set();
    dbFiles.forEach(file => {
      if (file.path) {
        const fileFullPath = path.resolve(process.cwd(), file.path);
        const basename = path.basename(fileFullPath);
        expectedFiles.add(basename);
      }
    });

    // Find orphaned files
    let deletedCount = 0;
    for (const uploadedFile of uploadedFiles) {
      if (!expectedFiles.has(uploadedFile)) {
        const filePath = path.join(uploadDir, uploadedFile);
        try {
          await fsPromises.unlink(filePath);
          console.log(`Deleted orphaned file: ${uploadedFile}`);
          deletedCount++;
        } catch (error) {
          console.error(`Error deleting orphaned file ${uploadedFile}:`, error);
        }
      }
    }

    console.log(`Cleanup completed. Deleted ${deletedCount} orphaned files.`);
    return deletedCount;
  } catch (error) {
    console.error('Error during orphaned files cleanup:', error);
    throw error;
  }
};

// Export the cleanup function for use in server.js
export { cleanupOrphanedFiles };

// Define uploads directory path
const UPLOADS_DIR = path.join(process.cwd(), 'uploads');

const router = express.Router();

// Setup multer for file uploads
const storage = multer.diskStorage({
  destination: "uploads/",
  filename: (req, file, cb) => {
    // Sanitize filename
    const sanitizedName = file.originalname.replace(/[^a-zA-Z0-9.-]/g, '_');
    cb(null, `${Date.now()}-${sanitizedName}`);
  }
});

const fileFilter = (req, file, cb) => {
  console.log('File upload attempt:', {
    originalName: file.originalname,
    mimetype: file.mimetype,
    size: file.size
  });

  // Accept all file types - security maintained through authentication
  console.log(`File filter: accepting all file types for authenticated upload`);
  cb(null, true);
};

const upload = multer({
  storage,
  fileFilter,
  limits: {
    fileSize: parseInt(process.env.MAX_FILE_SIZE) || 100 * 1024 * 1024, // Default 100MB if not set in env
    files: 10, // Maximum 10 files at once
    fieldSize: 2 * 1024 * 1024, // 2MB field size limit
  }
});

// Get all files (public download page) - Only returns actual file uploads, not links
router.get("/", async (req, res) => {
  try {
    // Get only actual files from database (exclude URL-type entries)
    const files = await File.find({ type: { $ne: 'url' } })
      .populate('categoryId', 'name description')
      .select('filename originalName path uploadedAt size type description categoryId downloadCount')
      .sort({ uploadedAt: -1 }); // Sort by upload date, newest first

    console.log(`Found ${files.length} actual file records in database`);

    // For each file, check if it exists in the filesystem
    const validFiles = await Promise.all(
      files.map(async (file) => {
        try {
          // For actual file uploads, validate filesystem
          if (!file.path || file.path.trim() === '') {
            console.warn(`File record missing path: ${file.filename} (${file._id})`);
            // Remove invalid file record
            try {
              await File.findByIdAndDelete(file._id);
            } catch (deleteError) {
              console.error(`Error deleting invalid file record ${file._id}:`, deleteError);
            }
            return null;
          }

          const fileFullPath = path.resolve(process.cwd(), file.path);
          console.log(`Checking file: ${file.filename} at ${fileFullPath}`);

          // Security check - ensure path is within uploads directory
          const uploadsDir = path.resolve(process.cwd(), 'uploads');
          if (!fileFullPath.startsWith(uploadsDir)) {
            console.error(`Security violation: File path outside uploads directory: ${fileFullPath}`);
            try {
              await File.findByIdAndDelete(file._id);
            } catch (deleteError) {
              console.error(`Error deleting security-violating file record ${file._id}:`, deleteError);
            }
            return null;
          }

          await fsPromises.access(fileFullPath);
          const stats = await fsPromises.stat(fileFullPath);

          if (!stats.isFile()) {
            console.warn(`Path exists but is not a file: ${fileFullPath}`);
            try {
              await File.findByIdAndDelete(file._id);
            } catch (deleteError) {
              console.error(`Error deleting non-file record ${file._id}:`, deleteError);
            }
            return null;
          }

          console.log(`File validated: ${file.filename} (${stats.size} bytes)`);
          return {
            ...file.toObject(),
            size: stats.size // Update with actual file size
          };
        } catch (error) {
          // If file doesn't exist in filesystem, remove it from database
          console.warn(`Removing orphaned file record: ${file.filename} (${file._id}) - ${error.message}`);
          try {
            await File.findByIdAndDelete(file._id);
          } catch (deleteError) {
            console.error(`Error deleting orphaned file record ${file._id}:`, deleteError);
          }
          return null;
        }
      })
    );

    // Filter out null entries (files that don't exist or are invalid)
    const existingFiles = validFiles.filter(file => file !== null);

    // Add displaySize property to each file for consistency with frontend expectations
    const filesWithDisplaySize = existingFiles.map(file => ({
      ...file,
      displaySize: formatBytes(file.size || 0)
    }));

    console.log("=== FILES API DEBUG ===");
    console.log(`Returning ${filesWithDisplaySize.length} valid files (only actual file uploads)`);
    console.log("Files data:", {
      filesType: typeof filesWithDisplaySize,
      filesIsArray: Array.isArray(filesWithDisplaySize),
      filesLength: filesWithDisplaySize?.length || 0,
      firstFileType: filesWithDisplaySize?.[0] ? typeof filesWithDisplaySize[0] : 'no files'
    });

    res.json(filesWithDisplaySize);
  } catch (error) {
    console.error('Error fetching files:', error);
    res.status(500).json({ message: 'Error fetching files' });
  }
});

// Direct file download endpoint
router.get("/download-direct/:filename", async (req, res) => {
  try {
    const filename = decodeURIComponent(req.params.filename);
    const filePath = path.join(UPLOADS_DIR, filename);

    // Prevent directory traversal
    if (!filePath.startsWith(UPLOADS_DIR)) {
      return res.status(403).json({ message: 'Access denied' });
    }

    // Ensure the file path is absolute and correct
    const absoluteFilePath = path.resolve(filePath);

    // Check if file exists
    try {
      await fsPromises.access(absoluteFilePath);
    } catch {
      return res.status(404).json({ message: 'File not found' });
    }

    // Get file stats
    const stats = await fsPromises.stat(absoluteFilePath);

    // Set headers
    res.setHeader('Content-Length', stats.size);
    res.setHeader('Content-Type', 'application/octet-stream');
    res.setHeader('Content-Disposition', `attachment; filename="${encodeURIComponent(filename)}"`);

    // Stream the file
    const fileStream = fs.createReadStream(absoluteFilePath);
    fileStream.on('error', error => {
      console.error('Stream error:', error);
      if (!res.headersSent) {
        res.status(500).json({ message: 'Error streaming file' });
      }
    });

    fileStream.pipe(res);
  } catch (error) {
    console.error('Download error:', error);
    if (!res.headersSent) {
      res.status(500).json({ message: 'Error downloading file' });
    }
  }
});

// Secure download endpoint
router.get("/download/:id", async (req, res) => {
  let fileStream = null;

  try {
    // Find file in database
    const file = await File.findById(req.params.id);
    if (!file) {
      console.error('File not found in database:', req.params.id);
      return res.status(404).json({ message: 'File not found' });
    }

    console.log('Download request for file:', {
      id: file._id,
      type: file.type,
      filename: file.filename,
      path: file.path
    });

    // Check if this is a URL type file (link) - should not happen via this endpoint
    if (file.type === 'url') {
      console.error('URL type file requested via download endpoint:', file._id);
      return res.status(400).json({ message: 'Cannot download URL type files directly. Use the frontend interface.' });
    }

    // Ensure we have a valid file path
    if (!file.path || file.path.trim() === '') {
      console.error('File record missing path:', file._id);
      return res.status(404).json({ message: 'File path not found' });
    }

    const filePath = path.resolve(process.cwd(), file.path);
    console.log('Resolved file path:', filePath);

    // Additional validation - ensure path is within uploads directory
    const uploadsDir = path.resolve(process.cwd(), 'uploads');
    if (!filePath.startsWith(uploadsDir)) {
      console.error('Security violation: Attempted path traversal', {
        fileId: file._id,
        requested: filePath,
        allowed: uploadsDir
      });
      return res.status(403).json({ message: 'Access denied' });
    }

    // Check if file exists in filesystem and is actually a file
    let stats;
    try {
      stats = await fsPromises.stat(filePath);
      console.log('File stats:', {
        exists: true,
        isFile: stats.isFile(),
        isDirectory: stats.isDirectory(),
        size: stats.size
      });

      if (!stats.isFile()) {
        console.error('Path is not a file (might be directory):', filePath);
        // If it's not a file, remove it from database
        try {
          await File.findByIdAndDelete(file._id);
          console.log('Removed invalid file record from database');
        } catch (deleteError) {
          console.error('Error deleting invalid file record:', deleteError);
        }
        return res.status(404).json({ message: 'File not found on server' });
      }
    } catch (err) {
      console.error('File access error:', err);
      // If file doesn't exist in filesystem, remove it from database
      try {
        await File.findByIdAndDelete(file._id);
        console.log('Removed orphaned file record from database');
      } catch (deleteError) {
        console.error('Error deleting orphaned file record:', deleteError);
      }
      return res.status(404).json({ message: 'File not found on server' });
    }

    // Set proper headers
    res.setHeader('Content-Disposition', `attachment; filename="${encodeURIComponent(file.filename)}"`);
    res.setHeader('Content-Type', 'application/octet-stream');
    res.setHeader('Content-Length', stats.size);

    console.log('Starting file stream for:', file.filename);

    // Create read stream
    fileStream = fs.createReadStream(filePath);

    // Handle stream errors
    fileStream.on('error', (error) => {
      console.error('Stream error:', error);
      if (!res.headersSent) {
        res.status(500).json({ message: 'Error streaming file' });
      }
    });

    // Handle stream end
    fileStream.on('end', () => {
      console.log('File stream ended successfully for:', file.filename);
      fileStream = null;
    });

    // Pipe the file
    fileStream.pipe(res);

    // Handle client disconnect
    res.on('close', () => {
      if (fileStream) {
        console.log('Client disconnected, destroying stream for:', file.filename);
        fileStream.destroy();
      }
    });

  } catch (error) {
    console.error('Download error:', error);
    if (fileStream) {
      fileStream.destroy();
    }
    if (!res.headersSent) {
      res.status(500).json({ message: 'Error downloading file' });
    }
  }
});


// Debug endpoint to test file upload
router.post("/debug-upload", protect, async (req, res) => {
  try {
    console.log('Debug upload request received:', {
      hasFile: !!req.file,
      bodyKeys: Object.keys(req.body),
      contentType: req.headers['content-type'],
      fileKeys: req.file ? Object.keys(req.file) : 'no file',
      multerFields: req.files ? 'present' : 'missing',
      multerFile: req.file ? {
        fieldname: req.file.fieldname,
        originalname: req.file.originalname,
        mimetype: req.file.mimetype,
        size: req.file.size
      } : 'no file'
    });

    res.json({
      message: 'Debug info received',
      hasFile: !!req.file,
      bodyKeys: Object.keys(req.body),
      contentType: req.headers['content-type'],
      fileInfo: req.file || 'no file'
    });
  } catch (error) {
    console.error('Debug upload error:', error);
    res.status(500).json({ message: 'Debug upload error', error: error.message });
  }
});

// Upload new file (admin only) - Use Multer as middleware
router.post("/upload", (req, res, next) => {
  // Pre-multer validation logging
  console.log('=== PRE-MULTER VALIDATION ===');
  console.log('Request validation:', {
    contentType: req.headers['content-type'],
    isMultipartFormData: req.headers['content-type']?.includes('multipart/form-data'),
    contentLength: req.headers['content-length'],
    hasAuthorization: !!req.headers.authorization,
    method: req.method,
    url: req.url,
    userAgent: req.headers['user-agent']?.substring(0, 100) // Truncate for readability
  });

  // Validate content type
  if (!req.headers['content-type']?.includes('multipart/form-data')) {
    console.error('Invalid content type for file upload:', req.headers['content-type']);
    return res.status(400).json({
      message: 'Invalid content type. File uploads must use multipart/form-data',
      expected: 'multipart/form-data',
      received: req.headers['content-type']
    });
  }

  // Validate authorization
  if (!req.headers.authorization) {
    console.error('Missing authorization header for file upload');
    return res.status(401).json({
      message: 'Authentication required for file uploads'
    });
  }

  next();
}, protect, upload.single('file'), async (req, res) => {
  try {
    // Enhanced logging for debugging
    console.log('=== FILE UPLOAD REQUEST ===');
    console.log('Headers:', {
      contentType: req.headers['content-type'],
      contentLength: req.headers['content-length'],
      authorization: req.headers.authorization ? 'Bearer [present]' : 'missing',
      userAgent: req.headers['user-agent']
    });
    console.log('Body fields:', {
      bodyKeys: req.body ? Object.keys(req.body) : 'no body',
      bodyValues: req.body ? Object.entries(req.body).reduce((acc, [key, value]) => {
        acc[key] = key.toLowerCase().includes('password') || key.toLowerCase().includes('token') ?
          '[hidden]' : value;
        return acc;
      }, {}) : 'no body',
      hasUrl: !!req.body?.url,
      hasCategoryId: !!req.body?.categoryId,
      hasDescription: !!req.body?.description
    });
    console.log('Multer processing:', {
      hasFile: !!req.file,
      hasFiles: !!req.files,
      fileKeys: req.file ? Object.keys(req.file) : 'no file',
      filesKeys: req.files ? Object.keys(req.files) : 'no files',
      multerFile: req.file ? {
        fieldname: req.file.fieldname,
        originalname: req.file.originalname,
        mimetype: req.file.mimetype,
        size: req.file.size,
        filename: req.file.filename,
        path: req.file.path
      } : 'no file'
    });

    // Field name validation
    if (req.file && req.file.fieldname !== 'file') {
      console.warn('Field name mismatch:', {
        expected: 'file',
        received: req.file.fieldname,
        suggestion: 'Ensure frontend form field name is "file"'
      });
    }

    // Check if req.files exists but req.file doesn't (field name mismatch)
    if (!req.file && req.files) {
      console.error('Field name mismatch detected:', {
        filesPresent: Object.keys(req.files),
        suggestion: 'Frontend is sending files but field name does not match "file"'
      });
    }

    // Extract fields from the form data (now properly parsed by Multer)
    const url = req.body?.url;
    const description = req.body?.description;
    const categoryId = req.body?.categoryId;
    const metadata = req.body?.metadata;

    // Check if this is a URL upload or file upload
    if (url) {
      // Handle URL upload
      if (!url.trim()) {
        return res.status(400).json({ message: 'URL is required for URL uploads' });
      }

      // Validate URL format
      try {
        new URL(url);
      } catch {
        return res.status(400).json({ message: 'Invalid URL format' });
      }

      // Extract filename from URL safely
      let filename = 'url-file';
      try {
        const urlObj = new URL(url);
        filename = urlObj.pathname.split('/').pop() || urlObj.hostname || 'url-file';
      } catch {
        filename = 'url-file';
      }

      const file = new File({
        filename: filename,
        originalName: url,
        path: '', // No file path for URLs
        type: 'url',
        url: url,
        categoryId: categoryId ? new mongoose.Types.ObjectId(categoryId) : null,
        size: 0, // No size for URLs
        description: description || '',
        metadata: metadata || {}
      });

      await file.save();
      res.status(201).json(file);
    } else {
      // Handle file upload
      console.log('Processing file upload...');

      if (!req.file) {
        console.error('No file received in multer middleware:', {
          hasFiles: !!req.files,
          filesKeys: req.files ? Object.keys(req.files) : 'none',
          contentType: req.headers['content-type'],
          bodyKeys: Object.keys(req.body || {}),
          suggestion: 'Check that the form field name is "file" and Content-Type is multipart/form-data'
        });

        let errorMessage = 'No file uploaded';
        if (req.files) {
          errorMessage += ' - field name mismatch. Ensure the file input field name is "file"';
        } else if (!req.headers['content-type']?.includes('multipart/form-data')) {
          errorMessage += ' - invalid content type. Ensure form is submitted as multipart/form-data';
        } else {
          errorMessage += ' - file was not received by server. Check file size limits and try again';
        }

        return res.status(400).json({
          message: errorMessage,
          details: process.env.NODE_ENV === 'development' ? {
            contentType: req.headers['content-type'],
            hasFiles: !!req.files,
            bodyKeys: Object.keys(req.body || {}),
            maxFileSize: process.env.MAX_FILE_SIZE || '100MB'
          } : undefined
        });
      }

      console.log('File upload successful:', req.file.filename);

      // Verify file exists and get stats
      let stats;
      try {
        stats = await fsPromises.stat(req.file.path);
        console.log('File stats retrieved:', {
          size: stats.size,
          path: req.file.path,
          isFile: stats.isFile(),
          isDirectory: stats.isDirectory(),
          created: stats.birthtime,
          modified: stats.mtime
        });
      } catch (statError) {
        console.error('File stat error:', {
          error: statError.message,
          code: statError.code,
          path: req.file.path,
          exists: statError.code === 'ENOENT' ? 'file not found' : 'other error',
          suggestion: statError.code === 'ENOENT' ?
            'File was uploaded but then deleted or moved' :
            'File system error occurred'
        });

        // Clean up the uploaded file if we can't access it
        try {
          await fsPromises.unlink(req.file.path);
          console.log('Cleaned up inaccessible file:', req.file.path);
        } catch (cleanupError) {
          console.error('Failed to cleanup after stat error:', cleanupError);
        }

        return res.status(500).json({
          message: 'File upload failed - unable to access uploaded file',
          details: process.env.NODE_ENV === 'development' ? {
            error: statError.message,
            code: statError.code,
            path: req.file.path
          } : undefined
        });
      }

      // Validate file size matches expected size
      if (Math.abs(stats.size - req.file.size) > 1024) { // Allow 1KB difference for metadata
        console.warn('File size mismatch:', { expected: req.file.size, actual: stats.size });
      }

      const file = new File({
        filename: req.file.filename,
        originalName: req.file.originalname,
        path: req.file.path,
        type: 'file',
        categoryId: categoryId ? new mongoose.Types.ObjectId(categoryId) : null,
        size: stats.size,
        description: description ? description.trim().substring(0, 500) : '', // Limit description length
        metadata: metadata || {}
      });

      await file.save();
      console.log('File saved to database successfully:', file._id);
      res.status(201).json(file);
    }
  } catch (error) {
    console.error('Upload error caught:', {
      message: error.message,
      stack: error.stack,
      status: error.status,
      hasFile: !!req.file,
      filePath: req.file?.path,
      bodyKeys: Object.keys(req.body || {}),
      timestamp: new Date().toISOString()
    });

    // Clean up uploaded file if database save fails
    if (req.file) {
      const fileFullPath = path.resolve(process.cwd(), req.file.path);
      try {
        await fsPromises.unlink(fileFullPath);
        console.log('Cleaned up uploaded file after error:', req.file.filename);
      } catch (cleanupError) {
        console.error('Failed to cleanup file:', {
          error: cleanupError.message,
          filePath: fileFullPath,
          originalFile: req.file.filename
        });
      }
    }

    // Determine appropriate status code and message
    let statusCode = error.status || 500;
    let errorMessage = error.message || 'Internal server error';

    // Provide more specific error messages based on error type
    if (error.message?.includes('authentication') || error.message?.includes('unauthorized')) {
      statusCode = 401;
      errorMessage = 'Authentication failed. Please log in again.';
    } else if (error.message?.includes('permission') || error.message?.includes('forbidden')) {
      statusCode = 403;
      errorMessage = 'You do not have permission to upload files.';
    } else if (error.message?.includes('file too large') || error.message?.includes('size')) {
      statusCode = 413;
      errorMessage = 'File is too large. Please choose a smaller file.';
    } else if (error.message?.includes('format') || error.message?.includes('type')) {
      statusCode = 415;
      errorMessage = 'File format not supported.';
    } else if (error.message?.includes('database') || error.message?.includes('mongo')) {
      statusCode = 503;
      errorMessage = 'Database error. Please try again later.';
    }

    res.status(statusCode).json({
      message: errorMessage,
      ...(process.env.NODE_ENV === 'development' && {
        originalError: error.message,
        stack: error.stack,
        fileInfo: req.file ? {
          filename: req.file.filename,
          size: req.file.size,
          mimetype: req.file.mimetype
        } : undefined
      })
    });
  }
});

// Test endpoint to verify server connectivity
router.get("/test", (req, res) => {
  res.json({ message: "File routes are working correctly", timestamp: new Date().toISOString() });
});

// Cleanup orphaned files endpoint (admin only)
router.post("/cleanup-orphaned", protect, async (req, res) => {
  try {
    console.log('Starting orphaned files cleanup...');

    // Get all file records from database
    const files = await File.find({ type: 'file' }); // Only check actual files, not URLs
    let cleanedCount = 0;
    const errors = [];

    for (const file of files) {
      try {
        // Check if file exists in filesystem
        const fileFullPath = path.resolve(process.cwd(), file.path);
        await fsPromises.access(fileFullPath);
      } catch {
        // File doesn't exist, remove from database
        console.warn(`Removing orphaned file record: ${file.filename}`);
        try {
          await File.findByIdAndDelete(file._id);
          cleanedCount++;
        } catch (deleteError) {
          console.error(`Error deleting orphaned file record ${file._id}:`, deleteError);
          errors.push(`Failed to delete ${file.filename}: ${deleteError.message}`);
        }
      }
    }

    res.json({
      message: `Cleanup completed. Removed ${cleanedCount} orphaned file records.`,
      cleanedCount,
      errors: errors.length > 0 ? errors : undefined
    });
  } catch (error) {
    console.error('Cleanup error:', error);
    res.status(500).json({
      message: 'Cleanup failed',
      error: error.message
    });
  }
});

// Upload link (public - no authentication required) - DEPRECATED: Use /api/links instead
router.post("/upload-link", async (req, res) => {
  try {
    console.log('Link upload request received (deprecated endpoint):', req.body);

    // Redirect to use the proper Link model instead of File model
    const linkData = {
      name: req.body.filename || 'Link',
      version: '1.0',
      description: req.body.description || '',
      downloadUrl: req.body.url,
      categoryId: req.body.categoryId,
      tags: [],
      fileSize: '',
      platform: 'Universal'
    };

    // Validate required fields
    if (!linkData.downloadUrl || !linkData.downloadUrl.trim()) {
      console.error('Link upload failed: URL is required');
      return res.status(400).json({ message: 'URL is required for link uploads' });
    }

    // Validate URL format
    try {
      new URL(linkData.downloadUrl.trim());
      console.log('URL validation passed for:', linkData.downloadUrl.trim());
    } catch (error) {
      console.error('Link upload failed: Invalid URL format:', linkData.downloadUrl.trim());
      return res.status(400).json({ message: 'Invalid URL format' });
    }

    // Check if category exists if provided
    if (linkData.categoryId) {
      const category = await Category.findById(linkData.categoryId);
      if (!category) {
        console.error('Link upload failed: Category not found:', linkData.categoryId);
        return res.status(400).json({ message: 'Category not found' });
      }
    }

    // Import Link model dynamically to avoid circular dependencies
    const { default: Link } = await import('../models/Link.js');

    const link = new Link(linkData);
    const savedLink = await link.save();

    // Populate category info for response
    await savedLink.populate('categoryId', 'name description');

    console.log('Link uploaded successfully to Link model:', {
      id: savedLink._id,
      name: savedLink.name,
      downloadUrl: savedLink.downloadUrl
    });

    res.status(201).json(savedLink);
  } catch (error) {
    console.error('Link upload error:', error);
    res.status(500).json({
      message: error.message || 'Internal server error'
    });
  }
});

// Delete file (admin only)
router.delete("/:id", protect, async (req, res) => {
  try {
    const file = await File.findById(req.params.id);
    if (!file) {
      return res.status(404).json({ message: 'File not found' });
    }

    // Delete file from filesystem
    try {
      const fileFullPath = path.resolve(process.cwd(), file.path);
      await fsPromises.unlink(fileFullPath);
    } catch (unlinkErr) {
      console.warn(`File not found on disk, skipping unlink: ${file.path}`, unlinkErr);
    }
    
    // Delete file record from database
    await File.findByIdAndDelete(req.params.id);
    
    res.json({ message: "File deleted successfully" });
  } catch (error) {
    res.status(500).json({ 
      message: error.message || 'Error deleting file'
    });
  }
});

router.put("/:id/category", protect, async (req, res) => {
  try {
    const { categoryId } = req.body;
    if (!categoryId) {
      return res.status(400).json({ message: 'Category ID is required' });
    }

    if (!mongoose.Types.ObjectId.isValid(categoryId)) {
      return res.status(400).json({ message: 'Invalid category ID' });
    }

    const category = await Category.findById(categoryId);
    if (!category) {
      return res.status(404).json({ message: 'Category not found' });
    }

    const file = await File.findByIdAndUpdate(
      req.params.id,
      { categoryId: new mongoose.Types.ObjectId(categoryId) },
      { new: true }
    ).populate('categoryId', 'name description');

    if (!file) {
      return res.status(404).json({ message: 'File not found' });
    }

    // Update file counts for old and new categories
    const currentFile = await File.findById(req.params.id);
    if (currentFile && currentFile.categoryId && currentFile.categoryId.toString() !== categoryId) {
      const oldCategory = await Category.findById(currentFile.categoryId);
      if (oldCategory) {
        oldCategory.fileCount = await File.countDocuments({ categoryId: oldCategory._id });
        await oldCategory.save();
      }
    }

    category.fileCount = await File.countDocuments({ categoryId: category._id });
    await category.save();

    res.json(file);
  } catch (error) {
    res.status(500).json({ message: error.message || 'Error updating file category' });
  }
});

router.get("/category/:categoryId", protect, async (req, res) => {
  try {
    if (!mongoose.Types.ObjectId.isValid(req.params.categoryId)) {
      return res.status(400).json({ message: 'Invalid category ID' });
    }

    const files = await File.find({ categoryId: req.params.categoryId })
      .populate('categoryId', 'name description')
      .select('filename originalName path uploadedAt size type description url categoryId downloadCount')
      .sort({ uploadedAt: -1 });

    res.json(files);
  } catch (error) {
    res.status(500).json({ message: error.message || 'Error fetching files by category' });
  }
});

router.put("/:id/download", protect, async (req, res) => {
   try {
     const file = await File.findByIdAndUpdate(
       req.params.id,
       { $inc: { downloadCount: 1 } },
       { new: true }
     ).select('downloadCount type url');

     if (!file) {
       console.error('File not found for download count update:', req.params.id);
       return res.status(404).json({ message: 'File not found' });
     }

     console.log('Download count updated for:', {
       id: req.params.id,
       type: file.type,
       newCount: file.downloadCount
     });

     res.json({ downloadCount: file.downloadCount });
   } catch (error) {
     console.error('Error updating download count:', error);
     res.status(500).json({ message: error.message || 'Error updating download count' });
   }
 });

// Update file metadata (admin only)
router.put("/:id", protect, async (req, res) => {
   try {
     const { description, originalName, categoryId } = req.body;

     if (!description && !originalName && !categoryId) {
       return res.status(400).json({ message: 'At least one field (description, originalName, or categoryId) is required' });
     }

     // Validate category if provided
     if (categoryId) {
       if (!mongoose.Types.ObjectId.isValid(categoryId)) {
         return res.status(400).json({ message: 'Invalid category ID' });
       }

       const category = await Category.findById(categoryId);
       if (!category) {
         return res.status(404).json({ message: 'Category not found' });
       }
     }

     // Build update object with only provided fields
     const updateData = {};
     if (description !== undefined) updateData.description = description;
     if (originalName !== undefined) updateData.originalName = originalName;
     if (categoryId !== undefined) updateData.categoryId = categoryId ? new mongoose.Types.ObjectId(categoryId) : null;

     const file = await File.findByIdAndUpdate(
       req.params.id,
       updateData,
       { new: true }
     ).populate('categoryId', 'name description');

     if (!file) {
       return res.status(404).json({ message: 'File not found' });
     }

     console.log('File metadata updated:', {
       id: file._id,
       updatedFields: Object.keys(updateData)
     });

     res.json(file);
   } catch (error) {
     console.error('Error updating file metadata:', error);
     res.status(500).json({ message: error.message || 'Error updating file metadata' });
   }
 });

export default router;
