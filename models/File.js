import mongoose from "mongoose";

const fileSchema = new mongoose.Schema({
  filename: String,
  originalName: String,
  path: String, // Local file path (legacy - empty for Cloudinary uploads)
  type: { type: String, enum: ["file", "url"], default: "file" },
  url: String, // External URL (for type='url') or Cloudinary URL (for type='file')
  categoryId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "Category",
    default: null,
  },
  uploadedAt: { type: Date, default: Date.now },
  description: String,
  size: Number, // in bytes
  downloadCount: { type: Number, default: 0 },
  metadata: { type: mongoose.Schema.Types.Mixed, default: {} },
  // Enhanced fields for better file management
  mimeType: { type: String, default: '' }, // MIME type for file type identification
  fileExtension: { type: String, default: '' }, // File extension for easier filtering and display
  // Cloudinary integration fields
  cloudinaryPublicId: { type: String, default: '' }, // Cloudinary public_id for file deletion and management
  cloudinaryUrl: { type: String, default: '' }, // Cloudinary secure URL for file access
  cloudinaryResourceType: { type: String, enum: ['image', 'video', 'raw', 'auto'], default: 'auto' }, // Cloudinary resource type (image, video, raw, or auto)
});

export default mongoose.model("File", fileSchema);
