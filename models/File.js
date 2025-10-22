import mongoose from "mongoose";

const fileSchema = new mongoose.Schema({
  filename: String,
  originalName: String,
  path: String,
  type: { type: String, enum: ["file", "url"], default: "file" },
  url: String,
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
});

export default mongoose.model("File", fileSchema);
