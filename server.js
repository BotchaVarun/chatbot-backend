require('dotenv').config();
const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const fs = require('fs');
const path = require('path');
const { CohereClient } = require('cohere-ai');

const User = require('./models/User');
const Chat = require('./models/Chat');

const app = express();
const PORT = 8080;

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname)));

// ======================== DATABASE CONNECTION ========================
mongoose.connect(process.env.MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true
}).then(() => console.log("✅ MongoDB connected"))
  .catch(err => console.error("❌ MongoDB error:", err));

// ======================== MIDDLEWARE ========================
function verifyToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  if (!authHeader) return res.status(401).json({ error: 'Token missing' });

  const token = authHeader.split(' ')[1];
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(403).json({ error: 'Invalid token' });
  }
}

const cohere = new CohereClient({ token: process.env.COHERE_API_KEY });

const dsaKeywords = [
  "sort", "stack", "queue", "tree", "graph", "heap", "hash",
  "search", "traversal", "linked list", "recursion", "algorithm",
  "binary", "complexity", "heap sort", "quick sort", "merge sort", "linear search",
  "binary search", "insertion sort", "selection sort", "bubble sort", "dsa"
];

// More flexible DSA detection
function isDSARelated(text) {
  const lower = text.toLowerCase();
  return dsaKeywords.some(keyword => lower.includes(keyword)) ||
    /tree|graph|list|sort|search|hash|queue|stack|algorithm|complexity/.test(lower);
}

// ======================== MULTER STORAGE ========================
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, 'uploads/'),
  filename: (req, file, cb) => cb(null, Date.now() + '-' + file.originalname)
});
const upload = multer({ storage });

function capitalize(str) {
  return str.charAt(0).toUpperCase() + str.slice(1);
}

// ======================== ENHANCE PROMPT ========================
function enhancePrompt(rawInput) {
  const lower = rawInput.toLowerCase();
  const possibleSections = {
    Introduction: ['introduction', 'intro', 'explain', 'overview'],
    Advantages: ['advantages', 'pros', 'benefits'],
    Disadvantages: ['disadvantages', 'cons', 'limitations'],
    Pseudocode: ['pseudocode', 'pseudo code', 'algorithm'],
    Applications: ['applications', 'uses', 'use cases'],
    Examples: ['examples', 'sample code', 'code examples']
  };

  let matchedSections = [];
  for (const [section, keywords] of Object.entries(possibleSections)) {
    if (keywords.some(word => lower.includes(word))) {
      matchedSections.push(section);
    }
  }

  const cleaned = rawInput.replace(
    /(introduction|intro|explain|overview|advantages|pros|benefits|disadvantages|cons|limitations|pseudocode|pseudo code|algorithm|applications|uses|use cases|examples|sample code|code examples)/gi,
    ''
  ).replace(/[^a-zA-Z0-9\s]/g, '').trim();

  const topic = cleaned || "DSA concept";
  if (matchedSections.length === 0) {
    matchedSections = ["Introduction", "Advantages", "Disadvantages", "Pseudocode", "Applications", "Examples"];
  }

  return `You are a highly skilled DSA tutor. 
Explain the concept of "${topic}" in detail. 
Cover the following sections in order:
${matchedSections.join(', ')}.
Use bullet points, examples, and simple language for clarity.`;
}

// ======================== PARSE ALGORITHM PROMPTS ========================
function parseOperationPrompt(prompt) {
  const lower = prompt.toLowerCase();
  const arrayMatch = prompt.match(/\[.*?\]/);
  const numberArray = arrayMatch ? arrayMatch[0].replace(/[\[\]\s]/g, '').split(',').map(Number) : null;
  const valueMatch = prompt.match(/find\s+(\d+)/i);
  const valueToFind = valueMatch ? parseInt(valueMatch[1]) : null;

  const operationMap = {
    'linear search': 'Linear Search',
    'binary search': 'Binary Search',
    'bubble sort': 'Bubble Sort',
    'selection sort': 'Selection Sort',
    'insertion sort': 'Insertion Sort',
    'quick sort': 'Quick Sort',
    'merge sort': 'Merge Sort',
    'heap sort': 'Heap Sort'
  };

  for (const [keyword, label] of Object.entries(operationMap)) {
    if (lower.includes(keyword)) {
      return {
        operation: label,
        array: numberArray,
        target: valueToFind
      };
    }
  }
  return null;
}

function buildExecutionPrompt(operation, array, target) {
  let prompt = `You are a DSA tutor. Show step-by-step ${operation} on the array: [${array.join(', ')}].\n`;
  if (target !== null) {
    prompt += `The element to find is: ${target}.\n`;
  }
  prompt += "Explain each iteration step-by-step in simple terms.";
  return prompt;
}

// ======================== AUTH ROUTES ========================
app.post('/auth/register', async (req, res) => {
  const { username, password } = req.body;
  const existing = await User.findOne({ username });
  if (existing) return res.status(400).json({ error: "Username taken" });

  const hashed = await bcrypt.hash(password, 10);
  const user = new User({ username, password: hashed });
  await user.save();

  const token = jwt.sign({ id: user._id, username }, process.env.JWT_SECRET);
  res.json({ token, username });
});

app.post('/auth/login', async (req, res) => {
  const { username, password } = req.body;
  const user = await User.findOne({ username });
  if (!user) return res.status(400).json({ error: "Invalid credentials" });

  const match = await bcrypt.compare(password, user.password);
  if (!match) return res.status(400).json({ error: "Invalid credentials" });

  const token = jwt.sign({ id: user._id, username }, process.env.JWT_SECRET);
  res.json({ token, username });
});

// ======================== CHAT ROUTES ========================
app.post('/chat/new', verifyToken, async (req, res) => {
  const chat = new Chat({
    userId: req.user.id,
    title: null,
    messages: [{ type: 'bot', text: '🤖 Hello! I am your DSA Tutor.' }]
  });
  await chat.save();
  res.json(chat);
});

app.post('/chat', verifyToken, async (req, res) => {
  const { message, chatId } = req.body;
  if (!isDSARelated(message)) {
    return res.json({ reply: '⚠️ Please ask only Data Structures & Algorithms related questions.' });
  }

  const parsed = parseOperationPrompt(message);
  const promptToSend = parsed
    ? buildExecutionPrompt(parsed.operation, parsed.array, parsed.target)
    : enhancePrompt(message);

  console.log("Prompt sent to Cohere:", promptToSend);

  try {
    const response = await cohere.chat({
      model: "command-r",
      message: promptToSend
    });

    const text = response.text;
    const chat = await Chat.findById(chatId);
    if (!chat) return res.status(404).json({ reply: "❌ Chat not found" });

    chat.messages.push({ type: 'user', text: message });
    chat.messages.push({ type: 'bot', text });
    await chat.save();

    res.json({ reply: text });
  } catch (err) {
    console.error("❌ Cohere API error:", err.message);
    res.status(500).json({ reply: "❌ Cohere API error" });
  }
});

app.post('/chat/file', verifyToken, upload.single('file'), async (req, res) => {
  const { message, chatId } = req.body;
  const filePath = req.file?.path;

  if (!filePath || !message) {
    return res.status(400).json({ reply: '⚠️ File or message missing' });
  }

  try {
    const fileContent = fs.readFileSync(filePath, 'utf8');
    const combined = `${message}\n\nFile Content:\n${fileContent}`;
    if (!isDSARelated(message) || !isDSARelated(fileContent)) {
      return res.json({ reply: '⚠️ The prompt or file is not related to Data Structures & Algorithms.' });
    }

    const parsed = parseOperationPrompt(combined);
    const promptToSend = parsed
      ? buildExecutionPrompt(parsed.operation, parsed.array, parsed.target)
      : enhancePrompt(combined);

    console.log("Prompt sent to Cohere (file):", promptToSend);

    const response = await cohere.chat({
      model: "command-r",
      message: promptToSend
    });

    const text = response.text;
    const chat = await Chat.findById(chatId);
    if (!chat) return res.status(404).json({ reply: "❌ Chat not found" });

    chat.messages.push({ type: 'user', text: message });
    chat.messages.push({ type: 'bot', text });
    await chat.save();

    res.json({ reply: text });
  } catch (err) {
    console.error("❌ File processing error:", err.message);
    res.status(500).json({ reply: '❌ Internal server error' });
  }
});

app.get('/chats', verifyToken, async (req, res) => {
  const chats = await Chat.find({ userId: req.user.id }).sort({ createdAt: -1 });
  res.json(chats);
});

app.post('/chat/rename', verifyToken, async (req, res) => {
  const { chatId, title } = req.body;
  const chat = await Chat.findOne({ _id: chatId, userId: req.user.id });
  if (!chat) return res.status(404).json({ error: 'Chat not found' });

  chat.title = title;
  await chat.save();
  res.json({ message: 'Renamed successfully' });
});

app.post('/chat/regenerate', verifyToken, async (req, res) => {
  const { chatId, userPrompt } = req.body;
  if (!isDSARelated(userPrompt)) {
    return res.json({ reply: '⚠️ Please ask only Data Structures & Algorithms related questions.' });
  }

  const parsed = parseOperationPrompt(userPrompt);
  const promptToSend = parsed
    ? buildExecutionPrompt(parsed.operation, parsed.array, parsed.target)
    : enhancePrompt(userPrompt);

  console.log("Prompt sent to Cohere (regenerate):", promptToSend);

  try {
    const response = await cohere.chat({
      model: "command-r",
      message: promptToSend
    });

    const text = response.text;
    const chat = await Chat.findById(chatId);
    if (!chat) return res.status(404).json({ reply: "❌ Chat not found" });

    chat.messages.push({ type: 'bot', text });
    await chat.save();

    res.json({ reply: text });
  } catch (err) {
    console.error("❌ Cohere API error:", err.message);
    res.status(500).json({ reply: "❌ Cohere API error" });
  }
});

app.delete('/chat/:id', verifyToken, async (req, res) => {
  await Chat.deleteOne({ _id: req.params.id, userId: req.user.id });
  res.json({ message: 'Deleted successfully' });
});

// ======================== START SERVER ========================
app.listen(PORT, () => {
  console.log(`🚀 Server running at http://localhost:${PORT}`);
});
