const express = require('express');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const sharp = require('sharp');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const app = express();

// Security middleware
app.use(helmet());
app.use(cors({
    origin: process.env.ALLOWED_ORIGINS ? process.env.ALLOWED_ORIGINS.split(',') : '*',
    methods: ['GET', 'POST', 'HEAD'],
    credentials: true
}));
app.use(express.json({ limit: '10mb' }));

// Rate limiting to prevent abuse
const uploadLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 20, // Limit each IP to 20 upload requests per windowMs
    message: 'Too many upload requests from this IP, please try again later.'
});

// CDN Configuration
const CDN_BASE_PATH = process.env.CDN_BASE_PATH || '/var/www/cdn/uploads';
const CDN_DOMAIN = process.env.CDN_DOMAIN || 'https://cdn.astrochachu.com';
const UPLOAD_TEMP_PATH = path.join(CDN_BASE_PATH, 'temp');
const JWT_SECRET = process.env.JWT_SECRET || '4c01990d1edeb2e349c500ee136020c0c94af1a2d259f44fe4b7bcee926da53c84bdc0cd8e3226bdc3936e0853813142d3cee2d52920a16a71340e4f097c10bc';

// Ensure required directories exist
[CDN_BASE_PATH, UPLOAD_TEMP_PATH].forEach(dir => {
    if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true, mode: 0o755 });
        console.log(`✅ Created directory: ${dir}`);
    }
});

// Allowed MIME types for images
const ALLOWED_MIME_TYPES = [
    'image/jpeg',
    'image/jpg',
    'image/png',
    'image/webp'
];

// Maximum file size: 5MB
const MAX_FILE_SIZE = 5 * 1024 * 1024;

/**
 * JWT Authentication Middleware
 * Verifies JWT token before allowing upload or file access
 */
function authenticateJWT(req, res, next) {
    const authHeader = req.headers.authorization;
    const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN

    if (!token) {
        return res.status(401).json({
            success: false,
            message: 'Access denied. No authentication token provided.'
        });
    }

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = decoded; // Attach user info to request
        req.astrologerId = decoded.id || decoded.astrologerId;
        next();
    } catch (error) {
        console.error('JWT verification failed:', error.message);
        return res.status(403).json({
            success: false,
            message: 'Invalid or expired token.'
        });
    }
}

/**
 * Advanced malware detection for image files
 * Checks for suspicious patterns, embedded scripts, and validates image structure
 */
async function performMalwareScan(filePath, mimeType) {
    const results = {
        isSafe: true,
        threats: [],
        warnings: []
    };

    try {
        // 1. Read file as buffer
        const fileBuffer = fs.readFileSync(filePath);
        
        // 2. Check for suspicious magic bytes that don't match the declared MIME type
        const magicBytes = fileBuffer.slice(0, 12);
        const validMagicBytes = validateMagicBytes(magicBytes, mimeType);
        if (!validMagicBytes.isValid) {
            results.isSafe = false;
            results.threats.push(`Invalid magic bytes: ${validMagicBytes.reason}`);
            return results;
        }

        // 3. Scan for embedded executable patterns
        const executablePatterns = [
            /MZ\x90\x00/g, // PE executable header
            /\x7fELF/g, // ELF executable header
            /<script[^>]*>/gi, // HTML script tags
            /javascript:/gi, // JavaScript protocol
            /vbscript:/gi, // VBScript protocol
            /on\w+\s*=/gi, // Event handlers (onclick, onerror, etc.)
            /<iframe/gi, // iframes
            /<object/gi, // object tags
            /<embed/gi, // embed tags
            /eval\s*\(/gi, // eval function
            /base64/gi, // Base64 encoding (potential obfuscation)
        ];

        const fileContent = fileBuffer.toString('utf-8', 0, Math.min(fileBuffer.length, 50000));
        
        executablePatterns.forEach((pattern, index) => {
            if (pattern.test(fileContent)) {
                results.isSafe = false;
                results.threats.push(`Suspicious pattern detected: ${pattern.source}`);
            }
        });

        // 4. Check for EXIF data exploits (polyglot files)
        try {
            const metadata = await sharp(filePath).metadata();
            
            // Validate image dimensions
            if (!metadata.width || !metadata.height) {
                results.isSafe = false;
                results.threats.push('Invalid image dimensions');
                return results;
            }

            // Check for suspiciously large dimensions (could be a zip bomb variant)
            if (metadata.width > 20000 || metadata.height > 20000) {
                results.isSafe = false;
                results.threats.push('Image dimensions exceed safe limits');
                return results;
            }

            // Check if file size is suspiciously small for declared dimensions
            const expectedSize = metadata.width * metadata.height;
            const actualSize = fileBuffer.length;
            if (actualSize < expectedSize * 0.001 && actualSize < 1000) {
                results.warnings.push('File size seems unusually small for image dimensions');
            }

        } catch (sharpError) {
            results.isSafe = false;
            results.threats.push('Failed to parse image: possibly corrupted or malicious');
            return results;
        }

        // 5. Check for null bytes in unexpected locations
        const nullByteCount = (fileBuffer.toString('binary').match(/\x00/g) || []).length;
        if (nullByteCount > fileBuffer.length * 0.1) { // More than 10% null bytes
            results.warnings.push('High number of null bytes detected');
        }

        // 6. Validate file extension matches content
        const ext = path.extname(filePath).toLowerCase();
        const expectedExts = {
            'image/jpeg': ['.jpg', '.jpeg'],
            'image/png': ['.png'],
            'image/webp': ['.webp']
        };

        if (expectedExts[mimeType] && !expectedExts[mimeType].includes(ext)) {
            results.warnings.push(`File extension (${ext}) doesn't match MIME type (${mimeType})`);
        }

        // 7. Check entropy (high entropy might indicate encryption/compression/obfuscation)
        const entropy = calculateEntropy(fileBuffer);
        if (entropy > 7.8) { // Very high entropy
            results.warnings.push(`High entropy detected (${entropy.toFixed(2)}): possible obfuscation`);
        }

    } catch (error) {
        console.error('❌ Malware scan error:', error);
        results.isSafe = false;
        results.threats.push(`Scan error: ${error.message}`);
    }

    return results;
}

/**
 * Validate magic bytes (file signatures)
 */
function validateMagicBytes(magicBytes, mimeType) {
    const signatures = {
        'image/jpeg': [
            [0xFF, 0xD8, 0xFF, 0xE0], // JPEG JFIF
            [0xFF, 0xD8, 0xFF, 0xE1], // JPEG EXIF
            [0xFF, 0xD8, 0xFF, 0xE2], // JPEG
            [0xFF, 0xD8, 0xFF, 0xE8], // JPEG
        ],
        'image/png': [
            [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A] // PNG
        ],
        'image/webp': [
            [0x52, 0x49, 0x46, 0x46] // RIFF (WebP starts with RIFF)
        ]
    };

    const expectedSignatures = signatures[mimeType];
    if (!expectedSignatures) {
        return { isValid: false, reason: 'Unsupported MIME type' };
    }

    const magicArray = Array.from(magicBytes);
    
    for (const signature of expectedSignatures) {
        const matches = signature.every((byte, index) => magicArray[index] === byte);
        if (matches) {
            return { isValid: true };
        }
    }

    return { 
        isValid: false, 
        reason: `Magic bytes don't match expected signature for ${mimeType}` 
    };
}

/**
 * Calculate Shannon entropy to detect obfuscation
 */
function calculateEntropy(buffer) {
    const frequency = {};
    const len = buffer.length;

    for (let i = 0; i < len; i++) {
        const byte = buffer[i];
        frequency[byte] = (frequency[byte] || 0) + 1;
    }

    let entropy = 0;
    for (const count of Object.values(frequency)) {
        const p = count / len;
        entropy -= p * Math.log2(p);
    }

    return entropy;
}

/**
 * Sanitize and optimize uploaded image
 */
async function sanitizeImage(inputPath, outputPath, documentType) {
    try {
        // Load image and strip all metadata (EXIF, IPTC, XMP)
        let pipeline = sharp(inputPath, { failOnError: true })
            .rotate() // Auto-rotate based on EXIF orientation
            .withMetadata({
                exif: {}, // Remove EXIF
                icc: undefined, // Remove ICC profile
            });

        // Apply document-specific optimizations
        switch (documentType) {
            case 'Profile Photo':
                // Profile photos: resize to standard size, optimize
                pipeline = pipeline
                    .resize(800, 800, { 
                        fit: 'cover', 
                        position: 'center' 
                    })
                    .jpeg({ quality: 85, progressive: true });
                break;

            case 'Aadhar Card':
            case 'Bank Passbook':
            case 'PAN Card':
                // Documents: maintain quality, compress lightly
                pipeline = pipeline
                    .resize(2000, 2000, { 
                        fit: 'inside', 
                        withoutEnlargement: true 
                    })
                    .jpeg({ quality: 90, progressive: true });
                break;

            default:
                // Default: moderate compression
                pipeline = pipeline
                    .resize(1600, 1600, { 
                        fit: 'inside', 
                        withoutEnlargement: true 
                    })
                    .jpeg({ quality: 85, progressive: true });
        }

        await pipeline.toFile(outputPath);
        
        console.log(`✅ Image sanitized and saved: ${outputPath}`);
        return { success: true };

    } catch (error) {
        console.error('❌ Image sanitization error:', error);
        return { success: false, error: error.message };
    }
}

/**
 * Generate secure filename
 */
function generateSecureFilename(originalName, astrologerId, documentType) {
    const ext = path.extname(originalName).toLowerCase();
    const timestamp = Date.now();
    const randomBytes = crypto.randomBytes(8).toString('hex');
    const hash = crypto.createHash('sha256')
        .update(`${astrologerId}-${documentType}-${timestamp}-${randomBytes}`)
        .digest('hex')
        .substring(0, 16);
    
    return `${astrologerId}_${documentType.replace(/\s+/g, '_')}_${timestamp}_${hash}${ext}`;
}

// Configure multer for temporary upload
const tempStorage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, UPLOAD_TEMP_PATH);
    },
    filename: (req, file, cb) => {
        const tempName = `temp_${Date.now()}_${crypto.randomBytes(8).toString('hex')}${path.extname(file.originalname)}`;
        cb(null, tempName);
    }
});

const upload = multer({
    storage: tempStorage,
    limits: {
        fileSize: MAX_FILE_SIZE,
        files: 4 // Maximum 4 files per request
    },
    fileFilter: (req, file, cb) => {
        // Validate MIME type
        if (!ALLOWED_MIME_TYPES.includes(file.mimetype)) {
            return cb(new Error(`Invalid file type: ${file.mimetype}. Only JPEG, PNG, and WebP are allowed.`));
        }
        
        // Validate file extension
        const ext = path.extname(file.originalname).toLowerCase();
        if (!['.jpg', '.jpeg', '.png', '.webp'].includes(ext)) {
            return cb(new Error(`Invalid file extension: ${ext}`));
        }
        
        cb(null, true);
    }
});

/**
 * Upload endpoint with malware scanning (JWT Protected)
 */
app.post('/upload', authenticateJWT, uploadLimiter, upload.single('file'), async (req, res) => {
    let tempFilePath = null;
    
    try {
        // Validate request
        if (!req.file) {
            return res.status(400).json({
                success: false,
                message: 'No file uploaded'
            });
        }

        const { documentType } = req.body;
        const astrologerId = req.astrologerId; // From JWT token

        if (!documentType) {
            // Clean up temp file
            fs.unlinkSync(req.file.path);
            return res.status(400).json({
                success: false,
                message: 'Missing required field: documentType'
            });
        }

        // Validate document type
        const validDocumentTypes = ['Aadhar Card', 'Bank Passbook', 'Profile Photo', 'PAN Card'];
        if (!validDocumentTypes.includes(documentType)) {
            fs.unlinkSync(req.file.path);
            return res.status(400).json({
                success: false,
                message: `Invalid document type: ${documentType}`
            });
        }

        tempFilePath = req.file.path;

        console.log(`📤 Processing upload: ${documentType} for astrologer ${astrologerId}`);

        // Perform malware scan
        console.log('🔍 Performing malware scan...');
        const scanResult = await performMalwareScan(tempFilePath, req.file.mimetype);

        if (!scanResult.isSafe) {
            // Delete malicious file immediately
            fs.unlinkSync(tempFilePath);
            
            console.error(`⚠️ Malicious file detected from astrologer ${astrologerId}:`, scanResult.threats);
            
            return res.status(400).json({
                success: false,
                message: 'File rejected: Security scan detected potential threats',
                threats: scanResult.threats
            });
        }

        if (scanResult.warnings.length > 0) {
            console.warn('⚠️ File warnings:', scanResult.warnings);
        }

        // Create astrologer directory structure
        const astrologerDir = path.join(CDN_BASE_PATH, 'astrologers', astrologerId.toString());
        const documentDir = path.join(astrologerDir, documentType);
        
        if (!fs.existsSync(documentDir)) {
            fs.mkdirSync(documentDir, { recursive: true, mode: 0o755 });
        }

        // Generate secure filename
        const secureFilename = generateSecureFilename(req.file.originalname, astrologerId, documentType);
        const finalPath = path.join(documentDir, secureFilename);

        // Sanitize and optimize image
        console.log('🧹 Sanitizing and optimizing image...');
        const sanitizeResult = await sanitizeImage(tempFilePath, finalPath, documentType);

        if (!sanitizeResult.success) {
            // Clean up temp file
            fs.unlinkSync(tempFilePath);
            
            return res.status(500).json({
                success: false,
                message: 'Failed to process image',
                error: sanitizeResult.error
            });
        }

        // Delete temp file after successful processing
        fs.unlinkSync(tempFilePath);

        // Generate CDN URL (requires JWT for access)
        const cdnUrl = `${CDN_DOMAIN}/cdn/file/astrologers/${astrologerId}/${encodeURIComponent(documentType)}/${secureFilename}`;

        // Get file stats
        const fileStats = fs.statSync(finalPath);

        console.log(`✅ File uploaded successfully: ${cdnUrl}`);

        res.status(200).json({
            success: true,
            message: 'File uploaded successfully',
            data: {
                url: cdnUrl,
                filename: secureFilename,
                documentType: documentType,
                size: fileStats.size,
                uploadedAt: new Date().toISOString()
            }
        });

    } catch (error) {
        console.error('❌ Upload error:', error);

        // Clean up temp file if it exists
        if (tempFilePath && fs.existsSync(tempFilePath)) {
            try {
                fs.unlinkSync(tempFilePath);
            } catch (unlinkError) {
                console.error('Error deleting temp file:', unlinkError);
            }
        }

        res.status(500).json({
            success: false,
            message: 'Upload failed',
            error: error.message
        });
    }
});

/**
 * Batch upload endpoint for multiple files (JWT Protected)
 */
app.post('/upload-batch', authenticateJWT, uploadLimiter, upload.fields([
    { name: 'aadharCard', maxCount: 1 },
    { name: 'bankPassbook', maxCount: 1 },
    { name: 'profilePhoto', maxCount: 1 },
    { name: 'pancard', maxCount: 1 }
]), async (req, res) => {
    const uploadedFiles = [];
    const errors = [];
    const tempFiles = [];

    try {
        const astrologerId = req.astrologerId; // From JWT token

        if (!req.files || Object.keys(req.files).length === 0) {
            return res.status(400).json({
                success: false,
                message: 'No files uploaded'
            });
        }

        // Map field names to document types
        const fieldToDocumentType = {
            'aadharCard': 'Aadhar Card',
            'bankPassbook': 'Bank Passbook',
            'profilePhoto': 'Profile Photo',
            'pancard': 'PAN Card'
        };

        // Process each file
        for (const [fieldName, files] of Object.entries(req.files)) {
            const file = files[0];
            const documentType = fieldToDocumentType[fieldName];
            tempFiles.push(file.path);

            try {
                // Perform malware scan
                const scanResult = await performMalwareScan(file.path, file.mimetype);

                if (!scanResult.isSafe) {
                    errors.push({
                        documentType,
                        error: 'Security scan failed',
                        threats: scanResult.threats
                    });
                    continue;
                }

                // Create directory structure
                const astrologerDir = path.join(CDN_BASE_PATH, 'astrologers', astrologerId.toString());
                const documentDir = path.join(astrologerDir, documentType);
                
                if (!fs.existsSync(documentDir)) {
                    fs.mkdirSync(documentDir, { recursive: true, mode: 0o755 });
                }

                // Generate secure filename and sanitize
                const secureFilename = generateSecureFilename(file.originalname, astrologerId, documentType);
                const finalPath = path.join(documentDir, secureFilename);

                const sanitizeResult = await sanitizeImage(file.path, finalPath, documentType);

                if (!sanitizeResult.success) {
                    errors.push({
                        documentType,
                        error: 'Image processing failed'
                    });
                    continue;
                }

                // Generate CDN URL (requires JWT for access)
                const cdnUrl = `${CDN_DOMAIN}/cdn/file/astrologers/${astrologerId}/${encodeURIComponent(documentType)}/${secureFilename}`;

                uploadedFiles.push({
                    documentType,
                    url: cdnUrl,
                    filename: secureFilename
                });

            } catch (fileError) {
                errors.push({
                    documentType,
                    error: fileError.message
                });
            }
        }

        // Clean up all temp files
        tempFiles.forEach(tempFile => {
            try {
                if (fs.existsSync(tempFile)) {
                    fs.unlinkSync(tempFile);
                }
            } catch (unlinkError) {
                console.error('Error deleting temp file:', unlinkError);
            }
        });

        // Return results
        if (uploadedFiles.length === 0) {
            return res.status(400).json({
                success: false,
                message: 'No files were uploaded successfully',
                errors
            });
        }

        res.status(200).json({
            success: true,
            message: `${uploadedFiles.length} file(s) uploaded successfully`,
            data: uploadedFiles,
            errors: errors.length > 0 ? errors : undefined
        });

    } catch (error) {
        console.error('❌ Batch upload error:', error);

        // Clean up all temp files
        tempFiles.forEach(tempFile => {
            try {
                if (fs.existsSync(tempFile)) {
                    fs.unlinkSync(tempFile);
                }
            } catch (unlinkError) {
                console.error('Error deleting temp file:', unlinkError);
            }
        });

        res.status(500).json({
            success: false,
            message: 'Batch upload failed',
            error: error.message
        });
    }
});

/**
 * Serve uploaded files with JWT authentication (Private URLs)
 * Files are NOT publicly accessible - JWT required
 */
app.get('/cdn/file/astrologers/:astrologerId/:documentType/:filename', authenticateJWT, (req, res) => {
    try {
        const { astrologerId, documentType, filename } = req.params;
        
        // Security: Verify the requesting user has permission to access this file
        // Only allow access to own files OR admin users
        if (req.astrologerId.toString() !== astrologerId.toString() && !req.user.isAdmin) {
            return res.status(403).json({
                success: false,
                message: 'Access denied. You can only access your own files.'
            });
        }

        // Construct file path
        const filePath = path.join(CDN_BASE_PATH, 'astrologers', astrologerId, documentType, filename);
        
        // Check if file exists
        if (!fs.existsSync(filePath)) {
            return res.status(404).json({
                success: false,
                message: 'File not found'
            });
        }

        // Security headers
        res.setHeader('X-Content-Type-Options', 'nosniff');
        res.setHeader('X-Frame-Options', 'DENY');
        res.setHeader('Cache-Control', 'private, max-age=86400'); // Private cache (not public)
        res.setHeader('Content-Security-Policy', "default-src 'none'; img-src 'self'; style-src 'none'; script-src 'none'");
        
        // Serve the file
        res.sendFile(filePath);
        
    } catch (error) {
        console.error('Error serving file:', error);
        res.status(500).json({
            success: false,
            message: 'Error serving file'
        });
    }
});

// Health check
app.get('/health', (req, res) => {
    res.json({
        success: true,
        message: 'CDN Server is running',
        timestamp: new Date().toISOString(),
        endpoints: {
            upload: 'POST /upload',
            batchUpload: 'POST /upload-batch',
            serve: 'GET /astrologers/{astrologerId}/{documentType}/{filename}'
        }
    });
});

// Error handling
app.use((error, req, res, next) => {
    console.error('Unhandled error:', error);
    
    // Clean up uploaded files on error
    if (req.file) {
        try {
            fs.unlinkSync(req.file.path);
        } catch (e) {}
    }
    if (req.files) {
        Object.values(req.files).flat().forEach(file => {
            try {
                fs.unlinkSync(file.path);
            } catch (e) {}
        });
    }

    res.status(500).json({
        success: false,
        message: error.message || 'Internal server error'
    });
});

// Start server
const PORT = process.env.CDN_PORT || 5000;
const HOST = process.env.CDN_HOST || '0.0.0.0';

app.listen(PORT, HOST, () => {
    console.log(`🚀 CDN Upload Server running on http://${HOST}:${PORT}`);
    console.log(`📁 CDN Base Path: ${CDN_BASE_PATH}`);
    console.log(`🌐 CDN Domain: ${CDN_DOMAIN}`);
    console.log(`🔒 JWT Authentication: ENABLED`);
    console.log(`✅ Malware scanning: ENABLED`);
    console.log(`✅ Image sanitization: ENABLED`);
    console.log(`⚠️  All URLs are PRIVATE (JWT required)`);
});

module.exports = app;
