/**
 * Utility functions for formatting
 */

/**
 * Format bytes into human readable format
 * @param {number} bytes - The number of bytes
 * @returns {string} Formatted string with appropriate unit
 */
export function formatBytes(bytes) {
  if (bytes === 0) return '0 Bytes';
  const k = 1024;
  const sizes = ['Bytes', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}