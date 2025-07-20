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

mongoose.connect("mongodb+srv://Venky:Venky%40123@chatbot.b9i5xrg.mongodb.net/dsabot?retryWrites=true&w=majority", {
  useNewUrlParser: true,
  useUnifiedTopology: true
}).then(() => console.log("✅ MongoDB connected"))
  .catch(err => console.error("❌ MongoDB error:", err));

function verifyToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  if (!authHeader) return res.status(401).json({ error: 'Token missing' });

  const token = authHeader.split(' ')[1];
  try {
    const decoded = jwt.verify(token, "jDbPwePcgYbtfchNRt6ZICYLodCs7YYuO8IgbzmB");
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(403).json({ error: 'Invalid token' });
  }
}


const cohere = new CohereClient({ token: "jDbPwePcgYbtfchNRt6ZICYLodCs7YYuO8IgbzmB" });

const dsaKeywords = [
  "sort", "stack", "queue", "tree", "graph", "heap", "hash",
  "search", "traversal", "linked list", "recursion", "algorithm",
  "binary", "complexity", "heap sort", "quick sort", "merge sort", "linear search",
  "binary search", "insertion sort", "selection sort", "bubble sort", "dsa"
];

function isDSARelated(text) {
  const lower = text.toLowerCase();
  return dsaKeywords.some(keyword => lower.includes(keyword));
}

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, 'uploads/'),
  filename: (req, file, cb) => cb(null, Date.now() + '-' + file.originalname)
});
const upload = multer({ storage });

function capitalize(str) {
  return str.charAt(0).toUpperCase() + str.slice(1);
}

// ✅ Enhanced for detecting ONLY ONE section (like 'pseudocode') and responding accordingly
function enhancePrompt(rawInput) {
  const lower = rawInput.toLowerCase();
  const possibleSections = {
    Introduction: ['introduction', 'intro'],
    Advantages: ['advantages', 'pros', 'benefits'],
    Disadvantages: ['disadvantages', 'cons', 'limitations'],
    Pseudocode: ['pseudocode', 'pseudo code', 'algorithm'],
    Applications: ['applications', 'uses', 'use cases'],
    Examples: ['examples', 'sample code', 'code examples']
  };

  const sections = [];
  let matchedSection = null;

  for (const [section, keywords] of Object.entries(possibleSections)) {
    if (keywords.some(word => lower.includes(word))) {
      matchedSection = section;
      sections.push(section);
    }
  }

  // Remove section-related keywords from the topic
  const cleaned = rawInput.replace(
    /(introduction|intro|advantages|pros|benefits|disadvantages|cons|limitations|pseudocode|pseudo code|algorithm|applications|uses|use cases|examples|sample code|code examples)/gi,
    ''
  ).replace(/[^a-zA-Z0-9\s]/g, '').trim();

  const topic = cleaned || "this concept";

  // Only include the matched section or all if none found
  const finalSections = matchedSection ? [matchedSection] : ["Introduction", "Advantages", "Disadvantages", "Pseudocode", "Applications", "Examples"];

  return `You are a helpful DSA tutor. Explain the concept "${topic}" with focus on:\n${finalSections.join('\n')}`;
}

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
  prompt += "Show step-by-step execution in a friendly and clear way with each iteration.";
  return prompt;
}

// Routes
app.post('/auth/register', async (req, res) => {
  const { username, password } = req.body;
  const existing = await User.findOne({ username });
  if (existing) return res.status(400).json({ error: "Username taken" });

  const hashed = await bcrypt.hash(password, 10);
  const user = new User({ username, password: hashed });
  await user.save();

  const token = jwt.sign({ id: user._id, username }, "jDbPwePcgYbtfchNRt6ZICYLodCs7YYuO8IgbzmB");
  res.json({ token, username });
});

app.post('/auth/login', async (req, res) => {
  const { username, password } = req.body;
  const user = await User.findOne({ username });
  if (!user) return res.status(400).json({ error: "Invalid credentials" });

  const match = await bcrypt.compare(password, user.password);
  if (!match) return res.status(400).json({ error: "Invalid credentials" });

  const token = jwt.sign({ id: user._id, username }, "jDbPwePcgYbtfchNRt6ZICYLodCs7YYuO8IgbzmB");
  res.json({ token, username });
});

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
  
  const parsed = parseOperationPrompt(message);
  const promptToSend = parsed
    ? buildExecutionPrompt(parsed.operation, parsed.array, parsed.target)
    : enhancePrompt(message);

  if (!isDSARelated(message)) {
    return res.json({ reply: '⚠️ Please ask only Data Structures & Algorithms related questions.' });
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

  try {
    const fileContent = fs.readFileSync(filePath, 'utf8');
    const combined = `${message}\n\nFile Content:\n${fileContent}`;
    const parsed = parseOperationPrompt(combined);
    const promptToSend = parsed
      ? buildExecutionPrompt(parsed.operation, parsed.array, parsed.target)
      : enhancePrompt(combined);

    if (!isDSARelated(message) || !isDSARelated(fileContent)) {
      return res.json({ reply: '⚠️ The prompt or file is not related to Data Structures & Algorithms.' });
    }

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

  const parsed = parseOperationPrompt(userPrompt);
  const promptToSend = parsed
    ? buildExecutionPrompt(parsed.operation, parsed.array, parsed.target)
    : enhancePrompt(userPrompt);

  if (!isDSARelated(userPrompt)) {
    return res.json({ reply: '⚠️ Please ask only Data Structures & Algorithms related questions.' });
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
