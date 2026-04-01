// server.js - Main Express Server for SAS-i Client Portal
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const multer = require('multer');
const path = require('path');
const nodemailer = require('nodemailer');
const twilio = require('twilio');
require('dotenv').config();
 
// Twilio Client Initialization
const twilioClient = process.env.TWILIO_ACCOUNT_SID && process.env.TWILIO_AUTH_TOKEN
    ? twilio(process.env.TWILIO_ACCOUNT_SID, process.env.TWILIO_AUTH_TOKEN)
    : null;
 
const app = express();
 
// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static('public'));
 
// Database Connection
mongoose.connect(process.env.MONGODB_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true
}).then(() => {
    console.log('✅ Connected to MongoDB');
}).catch(err => {
    console.error('❌ MongoDB connection error:', err);
});
 
// User Schema
const userSchema = new mongoose.Schema({
    email: { type: String, required: true, unique: true, lowercase: true },
    password: { type: String, required: true },
    name: { type: String, required: true },
    company: { type: String, required: true },
    phone: String,
    createdAt: { type: Date, default: Date.now },
    isActive: { type: Boolean, default: true }
});
 
const User = mongoose.model('User', userSchema);
 
// Project Schema
const projectSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    projectId: { type: String, required: true, unique: true },
    title: { type: String, required: true },
    type: { type: String, required: true },
    status: { type: String, enum: ['pending', 'in-progress', 'completed'], default: 'pending' },
    progress: { type: Number, default: 0 },
    startDate: { type: Date, default: Date.now },
    estimatedCompletion: Date,
    actualCompletion: Date,
    supportUntil: Date,
    documents: [{
        filename: String,
        originalName: String,
        uploadDate: { type: Date, default: Date.now },
        size: Number,
        type: String
    }],
    notes: String,
    aiAnalysis: {
        complianceScore: Number,
        issuesFound: Number,
        findings: [{
            section: String,
            severity: String,
            description: String
        }],
        analyzedAt: Date
    }
});
 
const Project = mongoose.model('Project', projectSchema);
 
// Message Schema
const messageSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    projectId: { type: mongoose.Schema.Types.ObjectId, ref: 'Project' },
    from: { type: String, required: true },
    subject: { type: String, required: true },
    body: { type: String, required: true },
    isRead: { type: Boolean, default: false },
    createdAt: { type: Date, default: Date.now }
});
 
const Message = mongoose.model('Message', messageSchema);
 
// Lead Schema (for contact form + SMS automation)
const leadSchema = new mongoose.Schema({
    name: { type: String, required: true },
    email: { type: String, required: true, lowercase: true },
    phone: { type: String, required: true },
    company: String,
    service: { type: String, required: true },
    message: String,
    consent: { type: Boolean, required: true },
    status: { 
        type: String, 
        enum: ['new', 'contacted', 'scheduled', 'completed', 'no-show'], 
        default: 'new' 
    },
    smsSent: { type: Boolean, default: false },
    smsDelivered: { type: Boolean, default: false },
    calendlyBooked: { type: Boolean, default: false },
    createdAt: { type: Date, default: Date.now },
    lastContactedAt: Date,
    notes: String
});
 
const Lead = mongoose.model('Lead', leadSchema);
 
// File Upload Configuration
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, 'uploads/');
    },
    filename: (req, file, cb) => {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, uniqueSuffix + '-' + file.originalname);
    }
});
 
const upload = multer({
    storage: storage,
    limits: { fileSize: 50 * 1024 * 1024 }, // 50MB limit
    fileFilter: (req, file, cb) => {
        const allowedTypes = /pdf|doc|docx|txt/;
        const extname = allowedTypes.test(path.extname(file.originalname).toLowerCase());
        const mimetype = allowedTypes.test(file.mimetype);
        
        if (mimetype && extname) {
            return cb(null, true);
        } else {
            cb(new Error('Only PDF, DOC, DOCX, and TXT files are allowed'));
        }
    }
});
 
// Email Configuration
const transporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: process.env.SMTP_PORT,
    secure: false,
    auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASS
    }
});
 
// Middleware: Verify JWT Token
const verifyToken = (req, res, next) => {
    const token = req.headers['authorization']?.split(' ')[1];
    
    if (!token) {
        return res.status(403).json({ message: 'No token provided' });
    }
    
    jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
        if (err) {
            return res.status(401).json({ message: 'Unauthorized' });
        }
        req.userId = decoded.id;
        next();
    });
};
 
// ============================================
// AUTHENTICATION ROUTES
// ============================================
 
// Register
app.post('/api/auth/register', async (req, res) => {
    try {
        const { email, password, name, company, phone } = req.body;
        
        // Check if user already exists
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ message: 'User already exists' });
        }
        
        // Hash password
        const hashedPassword = await bcrypt.hash(password, 10);
        
        // Create user
        const user = new User({
            email,
            password: hashedPassword,
            name,
            company,
            phone
        });
        
        await user.save();
        
        // Send welcome email
        await transporter.sendMail({
            from: process.env.SMTP_FROM,
            to: email,
            subject: 'Welcome to SAS-i Portal',
            html: `
                <h2>Welcome ${name}!</h2>
                <p>Thank you for registering with SAS-i.</p>
                <p>Your account has been created successfully. You can now log in to access your client portal.</p>
                <p>We look forward to helping you with your aviation certification needs.</p>
                <br>
                <p>Best regards,<br>SAS-i Team</p>
            `
        });
        
        res.status(201).json({ message: 'User registered successfully' });
    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({ message: 'Server error during registration' });
    }
});
 
// Login
app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        
        // Find user
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(401).json({ message: 'Invalid credentials' });
        }
        
        // Check password
        const isValidPassword = await bcrypt.compare(password, user.password);
        if (!isValidPassword) {
            return res.status(401).json({ message: 'Invalid credentials' });
        }
        
        // Generate token
        const token = jwt.sign(
            { id: user._id, email: user.email },
            process.env.JWT_SECRET,
            { expiresIn: '7d' }
        );
        
        res.json({
            token,
            user: {
                id: user._id,
                email: user.email,
                name: user.name,
                company: user.company
            }
        });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ message: 'Server error during login' });
    }
});
 
// ============================================
// USER ROUTES
// ============================================
 
// Get User Profile
app.get('/api/user/profile', verifyToken, async (req, res) => {
    try {
        const user = await User.findById(req.userId).select('-password');
        res.json(user);
    } catch (error) {
        res.status(500).json({ message: 'Error fetching profile' });
    }
});
 
// Update User Profile
app.put('/api/user/profile', verifyToken, async (req, res) => {
    try {
        const { name, company, phone } = req.body;
        const user = await User.findByIdAndUpdate(
            req.userId,
            { name, company, phone },
            { new: true }
        ).select('-password');
        res.json(user);
    } catch (error) {
        res.status(500).json({ message: 'Error updating profile' });
    }
});
 
// ============================================
// PROJECT ROUTES
// ============================================
 
// Get All Projects for User
app.get('/api/projects', verifyToken, async (req, res) => {
    try {
        const projects = await Project.find({ userId: req.userId }).sort({ startDate: -1 });
        res.json(projects);
    } catch (error) {
        res.status(500).json({ message: 'Error fetching projects' });
    }
});
 
// Get Single Project
app.get('/api/projects/:id', verifyToken, async (req, res) => {
    try {
        const project = await Project.findOne({ _id: req.params.id, userId: req.userId });
        if (!project) {
            return res.status(404).json({ message: 'Project not found' });
        }
        res.json(project);
    } catch (error) {
        res.status(500).json({ message: 'Error fetching project' });
    }
});
 
// Create New Project
app.post('/api/projects', verifyToken, async (req, res) => {
    try {
        const { title, type } = req.body;
        
        // Generate project ID
        const count = await Project.countDocuments();
        const projectId = `AAC-${new Date().getFullYear()}-${String(count + 1).padStart(3, '0')}`;
        
        const project = new Project({
            userId: req.userId,
            projectId,
            title,
            type,
            status: 'pending'
        });
        
        await project.save();
        
        // Send notification email
        const user = await User.findById(req.userId);
        await transporter.sendMail({
            from: process.env.SMTP_FROM,
            to: user.email,
            subject: `New Project Created: ${projectId}`,
            html: `
                <h2>New Project Created</h2>
                <p>Your project "${title}" has been created successfully.</p>
                <p><strong>Project ID:</strong> ${projectId}</p>
                <p><strong>Type:</strong> ${type}</p>
                <p>You can track progress in your client portal.</p>
            `
        });
        
        res.status(201).json(project);
    } catch (error) {
        console.error('Project creation error:', error);
        res.status(500).json({ message: 'Error creating project' });
    }
});
 
// Upload Document to Project
app.post('/api/projects/:id/upload', verifyToken, upload.array('files', 10), async (req, res) => {
    try {
        const project = await Project.findOne({ _id: req.params.id, userId: req.userId });
        if (!project) {
            return res.status(404).json({ message: 'Project not found' });
        }
        
        const uploadedFiles = req.files.map(file => ({
            filename: file.filename,
            originalName: file.originalname,
            size: file.size,
            type: file.mimetype
        }));
        
        project.documents.push(...uploadedFiles);
        await project.save();
        
        res.json({ message: 'Files uploaded successfully', files: uploadedFiles });
    } catch (error) {
        console.error('Upload error:', error);
        res.status(500).json({ message: 'Error uploading files' });
    }
});
 
// AI Pre-Check Analysis
app.post('/api/ai/precheck', verifyToken, upload.single('file'), async (req, res) => {
    try {
        // TODO: Integrate actual AI compliance software here
        // This is a placeholder that simulates AI analysis
        
        // Simulate AI processing delay
        await new Promise(resolve => setTimeout(resolve, 3000));
        
        // Generate mock AI analysis
        const analysis = {
            complianceScore: Math.floor(Math.random() * 20) + 80, // 80-100%
            issuesFound: Math.floor(Math.random() * 15) + 5, // 5-20 issues
            regulationsChecked: 156,
            findings: [
                {
                    section: 'Section 3.2 - Training Requirements',
                    severity: 'warning',
                    description: 'Missing reference to 14 CFR 135.293 initial and recurrent pilot testing requirements'
                },
                {
                    section: 'Section 5.1 - Equipment Requirements',
                    severity: 'warning',
                    description: 'Incomplete VFR equipment list per 14 CFR 135.159'
                },
                {
                    section: 'Section 2.1 - Management Structure',
                    severity: 'success',
                    description: 'Fully compliant with organizational requirements'
                }
            ],
            analyzedAt: new Date()
        };
        
        res.json(analysis);
    } catch (error) {
        console.error('AI precheck error:', error);
        res.status(500).json({ message: 'Error during AI analysis' });
    }
});
 
// ============================================
// MESSAGE ROUTES
// ============================================
 
// Get Messages for User
app.get('/api/messages', verifyToken, async (req, res) => {
    try {
        const messages = await Message.find({ userId: req.userId })
            .populate('projectId', 'projectId title')
            .sort({ createdAt: -1 });
        res.json(messages);
    } catch (error) {
        res.status(500).json({ message: 'Error fetching messages' });
    }
});
 
// Create New Message
app.post('/api/messages', verifyToken, async (req, res) => {
    try {
        const { projectId, subject, body } = req.body;
        const user = await User.findById(req.userId);
        
        const message = new Message({
            userId: req.userId,
            projectId: projectId || null,
            from: user.name,
            subject,
            body
        });
        
        await message.save();
        
        // Send email notification to admin
        await transporter.sendMail({
            from: process.env.SMTP_FROM,
            to: process.env.ADMIN_EMAIL,
            subject: `New Message from ${user.name}: ${subject}`,
            html: `
                <h3>New message from client</h3>
                <p><strong>From:</strong> ${user.name} (${user.email})</p>
                <p><strong>Company:</strong> ${user.company}</p>
                <p><strong>Subject:</strong> ${subject}</p>
                <p><strong>Message:</strong></p>
                <p>${body}</p>
            `
        });
        
        res.status(201).json(message);
    } catch (error) {
        console.error('Message creation error:', error);
        res.status(500).json({ message: 'Error sending message' });
    }
});
 
// Mark Message as Read
app.put('/api/messages/:id/read', verifyToken, async (req, res) => {
    try {
        const message = await Message.findOneAndUpdate(
            { _id: req.params.id, userId: req.userId },
            { isRead: true },
            { new: true }
        );
        res.json(message);
    } catch (error) {
        res.status(500).json({ message: 'Error updating message' });
    }
});
 
// ============================================
// DASHBOARD STATS
// ============================================
 
app.get('/api/dashboard/stats', verifyToken, async (req, res) => {
    try {
        const activeProjects = await Project.countDocuments({ 
            userId: req.userId, 
            status: { $in: ['pending', 'in-progress'] } 
        });
        
        const completedProjects = await Project.countDocuments({ 
            userId: req.userId, 
            status: 'completed' 
        });
        
        const totalDocuments = await Project.aggregate([
            { $match: { userId: mongoose.Types.ObjectId(req.userId) } },
            { $project: { documentCount: { $size: '$documents' } } },
            { $group: { _id: null, total: { $sum: '$documentCount' } } }
        ]);
        
        // Calculate support days remaining (for most recent completed project)
        const completedProject = await Project.findOne({
            userId: req.userId,
            status: 'completed',
            supportUntil: { $exists: true }
        }).sort({ supportUntil: -1 });
        
        let supportDaysLeft = 0;
        if (completedProject && completedProject.supportUntil) {
            const today = new Date();
            const supportEnd = new Date(completedProject.supportUntil);
            supportDaysLeft = Math.max(0, Math.ceil((supportEnd - today) / (1000 * 60 * 60 * 24)));
        }
        
        res.json({
            activeProjects,
            completedProjects,
            totalDocuments: totalDocuments.length > 0 ? totalDocuments[0].total : 0,
            supportDaysLeft
        });
    } catch (error) {
        console.error('Stats error:', error);
        res.status(500).json({ message: 'Error fetching stats' });
    }
});
 
// ============================================
// CONTACT FORM + SMS AUTOMATION
// ============================================
 
app.post('/api/contact/calendly-sms', async (req, res) => {
    try {
        const { name, email, phone, company, service, message, consent } = req.body;
        
        console.log('📞 New contact form submission:', { name, email, phone, service });
        
        // Validate required fields
        if (!name || !email || !phone || !service) {
            return res.status(400).json({ 
                message: 'Missing required fields: name, email, phone, and service are required' 
            });
        }
        
        // Verify consent
        if (!consent) {
            return res.status(400).json({ 
                message: 'SMS consent is required to use this service' 
            });
        }
        
        // Clean phone number (remove all non-digits)
        const cleanPhone = phone.replace(/\D/g, '');
        
        // Validate phone number (must be 10 digits for US)
        if (cleanPhone.length !== 10) {
            return res.status(400).json({ 
                message: 'Invalid phone number. Please enter a valid 10-digit US phone number.' 
            });
        }
        
        // Save lead to database
        const lead = new Lead({
            name,
            email,
            phone: cleanPhone,
            company: company || '',
            service,
            message: message || '',
            consent
        });
        
        await lead.save();
        console.log('💾 Lead saved to database:', lead._id);
        
        // Send SMS with Calendly link
        const calendlyLink = process.env.CALENDLY_LINK || 'https://calendly.com/sas-international';
        const twilioPhone = `+1${cleanPhone}`;
        
        try {
            if (!twilioClient) {
                console.error('❌ Twilio client not initialized - check TWILIO_ACCOUNT_SID and TWILIO_AUTH_TOKEN');
            } else {
                const smsBody = `Hi ${name}! Thanks for contacting SAS-i (Strategic Aviation Solutions International). We'd love to discuss your ${service} needs.\n\nSchedule your free consultation here:\n${calendlyLink}\n\n- SAS-i Team\nReply STOP to opt-out`;
                
                const smsResult = await twilioClient.messages.create({
                    body: smsBody,
                    from: process.env.TWILIO_PHONE_NUMBER,
                    to: twilioPhone
                });
                
                console.log('📱 SMS sent successfully:', smsResult.sid);
                
                lead.smsSent = true;
                lead.smsDelivered = (smsResult.status === 'sent' || smsResult.status === 'queued');
                await lead.save();
            }
        } catch (smsError) {
            console.error('❌ SMS send failed:', smsError.message);
            // Don't fail the entire request if SMS fails
        }
        
        // Send email notification to admin
        try {
            await transporter.sendMail({
                from: process.env.SMTP_FROM,
                to: process.env.ADMIN_EMAIL || 'info@sas-international.com',
                subject: `🔔 New Lead: ${name} - ${service}`,
                html: `
                    <div style="font-family: Arial, sans-serif; max-width: 600px;">
                        <h2 style="color: #00d4ff;">New Consultation Request</h2>
                        <p><strong>Name:</strong> ${name}</p>
                        <p><strong>Email:</strong> <a href="mailto:${email}">${email}</a></p>
                        <p><strong>Phone:</strong> <a href="tel:+1${cleanPhone}">${phone}</a></p>
                        <p><strong>Company:</strong> ${company || 'Not provided'}</p>
                        <p><strong>Service:</strong> ${service}</p>
                        ${message ? `<p><strong>Message:</strong> ${message}</p>` : ''}
                        <p><strong>SMS Status:</strong> ${lead.smsSent ? '✅ Sent' : '❌ Failed'}</p>
                    </div>
                `
            });
            console.log('📧 Admin notification email sent');
        } catch (emailError) {
            console.error('❌ Admin email failed:', emailError.message);
        }
        
        // Send confirmation email to lead
        try {
            await transporter.sendMail({
                from: process.env.SMTP_FROM,
                to: email,
                subject: 'SAS-i - Thank You for Your Inquiry',
                html: `
                    <div style="font-family: Arial, sans-serif; max-width: 600px;">
                        <h2 style="color: #00d4ff;">Thank You, ${name}!</h2>
                        <p>We received your inquiry about <strong>${service}</strong> and will be in touch shortly.</p>
                        <p>In the meantime, feel free to schedule a consultation at your convenience:</p>
                        <p><a href="${calendlyLink}" style="display: inline-block; background: #00d4ff; color: #000; padding: 12px 24px; border-radius: 5px; text-decoration: none; font-weight: bold;">Schedule Consultation</a></p>
                        <br>
                        <p>Best regards,<br><strong>SAS-i Team</strong><br>Strategic Aviation Solutions International</p>
                    </div>
                `
            });
            console.log('📧 Lead confirmation email sent');
        } catch (emailError) {
            console.error('❌ Lead email failed:', emailError.message);
        }
        
        res.status(200).json({ 
            message: 'Thank you! Check your phone for a scheduling link.',
            leadId: lead._id
        });
        
    } catch (error) {
        console.error('❌ Contact form error:', error);
        res.status(500).json({ message: 'Server error processing your request. Please try again.' });
    }
});
 
// Get All Leads (Admin)
app.get('/api/admin/leads', verifyToken, async (req, res) => {
    try {
        const leads = await Lead.find().sort({ createdAt: -1 });
        res.json(leads);
    } catch (error) {
        res.status(500).json({ message: 'Error fetching leads' });
    }
});
 
// ============================================
// HEALTH CHECK
// ============================================
 
app.get('/health', (req, res) => {
    res.json({ status: 'ok', message: 'Server is running' });
});
 
// ============================================
// START SERVER
// ============================================
 
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`🚀 Server running on port ${PORT}`);
    console.log(`📊 Environment: ${process.env.NODE_ENV || 'development'}`);
});
 
module.exports = app;
 
