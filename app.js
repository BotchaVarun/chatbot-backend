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
const PORT = 3000;

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname)));

// MongoDB Connection
mongoose.connect(process.env.MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true
}).then(() => console.log("✅ MongoDB connected"))
  .catch(err => console.error("❌ MongoDB error:", err));

// JWT Auth Middleware
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

// Cohere Init
const cohere = new CohereClient({ token: process.env.COHERE_API_KEY });

// ✅ DSA + DAA Keywords
const dsaKeywords = [
  // DSA Topics
  "sort", "stack", "queue", "tree", "graph", "heap", "hash",
  "search", "traversal", "linked list", "recursion", "algorithm",
  "binary", "heapsort", "quicksort", "mergesort", "linearsearch",
  "binarysearch", "insertionsort", "selectionsort", "bubblesort",
  "avl tree", "segment tree", "trie", "union find", "topological",
  "dijkstra", "prim", "kruskal", "tarjan", "kosaraju",
  // DAA Topics
  "greedy", "divide and conquer", "dynamic programming", "dp",
  "branch and bound", "backtracking", "time complexity", "space complexity",
  "asymptotic notations", "big o", "complexity", "daa"
];

// ✅ DSA/DAA Detection
function isDSARelated(text) {
  const lower = text.toLowerCase();
  return dsaKeywords.some(keyword => lower.includes(keyword));
}

// ✅ Detects user wants ONLY complexity
function wantsComplexityOnly(prompt) {
  const lower = prompt.toLowerCase();
  return /time complexity|space complexity|big o|what is the complexity/.test(lower);
}

// ✅ File Upload (Multer)
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, 'uploads/'),
  filename: (req, file, cb) => cb(null, Date.now() + '-' + file.originalname)
});
const upload = multer({ storage });

// ✅ Operation Execution Parser
function parseOperationPrompt(prompt) {
  const lower = prompt.toLowerCase();
  const arrayMatch = prompt.match(/\[.*?\]/);
  const numberArray = arrayMatch ? arrayMatch[0].replace(/[\[\]\s]/g, '').split(',').map(Number) : null;
  const valueMatch = prompt.match(/find\s+(\d+)/i);
  const valueToFind = valueMatch ? parseInt(valueMatch[1]) : null;

  const operationMap = {
    'Linear Search': 'LS',
    'bubble sort': 'bubble Sort',
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
  prompt += "Show each iteration clearly and explain how it works.";
  return prompt;
}

// ✅ Enhanced Structured Prompt Generator
function enhancePrompt(rawInput) {
  const lower = rawInput.toLowerCase();
  const possibleSections = {
    Introduction: ['introduction', 'intro'],
    Advantages: ['advantages', 'pros', 'benefits'],
    Disadvantages: ['disadvantages', 'cons', 'limitations'],
    Pseudocode: ['pseudocode', 'pseudo code', 'algorithm'],
    Applications: ['applications', 'uses', 'use cases'],
    Examples: ['examples', 'sample code', 'code examples'],
    Complexity: ['complexity', 'time complexity', 'space complexity', 'big o']
  };

  let matchedSection = null;
  for (const [section, keywords] of Object.entries(possibleSections)) {
    if (keywords.some(word => lower.includes(word))) {
      matchedSection = section;
      break;
    }
  }

  const cleaned = rawInput.replace(
    /(introduction|intro|advantages|pros|benefits|disadvantages|cons|limitations|pseudocode|pseudo code|algorithm|applications|uses|use cases|examples|sample code|code examples|complexity|time complexity|space complexity|big o)/gi,
    ''
  ).replace(/[^a-zA-Z0-9\s]/g, '').trim();

  const topic = cleaned || "this concept";
  const finalSections = matchedSection
    ? [matchedSection]
    : ["Introduction", "Advantages", "Disadvantages", "Pseudocode", "Complexity", "Applications", "Examples"];

  return `You are a helpful DSA/DAA tutor. Explain the concept "${topic}" with focus on:\n${finalSections.join('\n')}`;
}

// ✅ Auth Routes
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

// ✅ Chat Routes
app.post('/chat/new', verifyToken, async (req, res) => {
  const chat = new Chat({
    userId: req.user.id,
    title: null,
    messages: [{ type: 'bot', text: '🤖 Hello! I am your DSA/DAA Tutor.' }]
  });
  await chat.save();
  res.json(chat);
});

app.post('/chat', verifyToken, async (req, res) => {
  const { message, chatId } = req.body;

  if (!isDSARelated(message)) {
    return res.json({ reply: '⚠️ Please ask only DSA or DAA related questions.' });
  }

  let promptToSend;

  if (wantsComplexityOnly(message)) {
    promptToSend = `You are a DSA/DAA expert. Provide only time and space complexities (best, average, worst) for: ${message}`;
  } else {
    const parsed = parseOperationPrompt(message);
    promptToSend = parsed
      ? buildExecutionPrompt(parsed.operation, parsed.array, parsed.target)
      : enhancePrompt(message);
  }

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

  const fileContent = fs.readFileSync(filePath, 'utf8');
  const combined = `${message}\n\nFile Content:\n${fileContent}`;

  if (!isDSARelated(message) && !isDSARelated(fileContent)) {
    return res.json({ reply: '⚠️ The prompt or file is not related to DSA/DAA.' });
  }

  const promptToSend = enhancePrompt(combined);

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
    return res.json({ reply: '⚠️ Please ask only DSA/DAA related questions.' });
  }

  let promptToSend;

  if (wantsComplexityOnly(userPrompt)) {
    promptToSend = `You are a DSA/DAA expert. Provide only time and space complexities for: ${userPrompt}`;
  } else {
    const parsed = parseOperationPrompt(userPrompt);
    promptToSend = parsed
      ? buildExecutionPrompt(parsed.operation, parsed.array, parsed.target)
      : enhancePrompt(userPrompt);
  }

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

app.listen(PORT, () => {
  console.log(`🚀 Server running at http://localhost:${PORT}`);
});
