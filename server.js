// server.js
const express = require("express");
const multer = require("multer");
const fs = require("fs");
const path = require("path");
const Tesseract = require("tesseract.js");
const pdfParse = require("pdf-parse");
const axios = require("axios");
const whois = require("whois-json");
const dns = require("dns").promises;
const { exiftool } = require("exiftool-vendored");

const app = express();
const PORT = 3000;

// static frontend
app.use(express.static(path.join(__dirname, "public")));
app.use(express.json({ limit: "2mb" }));

// multer uploads
const upload = multer({ dest: "uploads/" });

// small helper to add flags and compute score
function addFlag(flags, key, reason, weight = 1, explanation = "") {
  flags.push({ key, reason, weight, explanation });
}
function computeLabel(flags) {
  const score = flags.reduce((s, f) => s + (f.weight || 0), 0);
  let label = "Low Risk";
  if (score >= 6) label = "High Risk";
  else if (score >= 3) label = "Medium Risk";
  return { score, label };
}

// Endpoint: Upload file (image/pdf/txt)
app.post("/upload", upload.single("file"), async (req, res) => {
  if (!req.file) return res.status(400).send({ error: "No file uploaded" });
  const filePath = req.file.path;
  const mimetype = req.file.mimetype || "";
  const flags = [];
  let extractedText = "";

  try {
    // --- PDF ---
    if (mimetype === "application/pdf" || req.file.originalname.toLowerCase().endsWith(".pdf")) {
      const buffer = fs.readFileSync(filePath);
      const data = await pdfParse(buffer);
      extractedText = data.text || "";

      // heuristics
      if (/fake|sample|demo|test|unofficial/i.test(extractedText)) {
        addFlag(flags, "suspicious_text", "Suspicious words found (fake/sample/demo)", 3, "Document contains explicit 'fake/sample/demo' words.");
      }
      // metadata checks via pdf-parse (info)
      if (data.info) {
        const info = data.info;
        if (info.ModDate && info.CreationDate && info.ModDate !== info.CreationDate) {
          addFlag(flags, "pdf_modified", "PDF modification date differs from creation date", 1, "PDF modification date not equal to creation date.");
        }
        if (info.Producer && /convert|online|printer|scan/i.test(info.Producer)) {
          addFlag(flags, "pdf_producer", `Producer: ${info.Producer}`, 1, "Produced/converted by common online tools (possible re-scan).");
        }
      }
    }

    // --- IMAGE ---
    else if (mimetype.startsWith("image/") || /\.(jpe?g|png|gif|bmp|tiff)$/i.test(req.file.originalname)) {
      // EXIF metadata
      try {
        const meta = await exiftool.read(filePath);
        // If very little metadata -> suspicious
        if (!meta || !meta.sourceFile) {
          addFlag(flags, "no_exif", "Image EXIF metadata missing", 1, "Image lacks camera metadata; suspicious for edited images.");
        } else {
          // check for creation dates
          if (!meta.DateTimeOriginal && !meta.CreateDate) {
            addFlag(flags, "no_dates", "No camera date in EXIF", 1, "Image EXIF has no creation date.");
          }
          // if filename suggests editing software
          if ((meta.Software && /photoshop|gimp|canva|paint/i.test(meta.Software)) || (meta.Producer && /convert|imagemagick/i.test(meta.Producer))) {
            addFlag(flags, "edited_software", `Image software: ${meta.Software || meta.Producer}`, 2, "Image was processed/edited by software.");
          }
        }
      } catch (exifErr) {
        // exiftool may fail on some images, ignore
      }

      // OCR
      try {
        const result = await Tesseract.recognize(filePath, "eng");
        extractedText = result.data.text || "";
        if (/fake|sample|demo|unofficial/i.test(extractedText)) {
          addFlag(flags, "suspicious_text_img", "Suspicious words found in image text", 3, "Image OCR contains explicit suspicious words.");
        }
        // suspicious financial/otp words
        if (/otp|verify your account|upi|account number|cvv|password|pay now|transfer/i.test(extractedText)) {
          addFlag(flags, "phishy_text", "Phishing-like financial text found", 3, "Text asks for sensitive financial info.");
        }
      } catch (ocrErr) {
        // ignore OCR failures
      }
    }

    // --- TXT or other plain text ---
    else if (mimetype === "text/plain" || req.file.originalname.toLowerCase().endsWith(".txt")) {
      extractedText = fs.readFileSync(filePath, "utf-8");
      if (/fake|sample|demo|unofficial/i.test(extractedText)) {
        addFlag(flags, "susp_text_txt", "Suspicious words in text", 3, "Text contains demo/fake markers.");
      }
      if (/verify your account|urgent|immediately|pay now|account number|upi|phonepe|google pay/i.test(extractedText)) {
        addFlag(flags, "phish_txt", "Phishing-like wording in text", 3, "Text contains urgent financial requests.");
      }
    } else {
      // Try to OCR as fallback for unknown types
      try {
        const result = await Tesseract.recognize(filePath, "eng");
        extractedText = result.data.text || "";
      } catch (e) {}
    }

    // If text contains URLs or emails -> quick domain checks
    let urlMatch = (extractedText.match(/https?:\/\/[^\s)'"`<>]+/gi) || []);
    let emailMatch = (extractedText.match(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-z]{2,}/gi) || []);

    if (emailMatch.length) {
      const email = emailMatch[0];
      addFlag(flags, "found_email", `Found email: ${email}`, 0, "Email extracted from document.");
      const domain = email.split("@").pop();
      try {
        await dns.lookup(domain);
      } catch (e) {
        addFlag(flags, "email_domain_bad", `Email domain ${domain} not resolvable`, 2, "Email domain DNS lookup failed.");
      }
    }

    if (urlMatch.length) {
      const firstUrl = urlMatch[0];
      addFlag(flags, "found_url", `Found URL: ${firstUrl}`, 0, "URL extracted from document.");
      // WHOIS + age check (best-effort)
      try {
        let hostname = new URL(firstUrl).hostname;
        const who = await whois(hostname).catch(()=>null);
        if (who && (who.createdDate || who.creationDate || who.created)) {
          const createdRaw = who.createdDate||who.creationDate||who.created;
          const created = new Date(createdRaw);
          if (!isNaN(created.getTime())) {
            const days = Math.round((Date.now() - created.getTime())/(1000*60*60*24));
            if (days < 30) addFlag(flags, "url_young", `Domain created ${days} days ago`, 2, "Domain is very new.");
          }
        }
      } catch(e){ /* ignore whois failures */ }
    }

    // final label & score
    const { score, label } = computeLabel(flags);
    // cleanup uploaded file
    try { fs.unlinkSync(filePath); } catch(e){}

    res.json({
      type: mimetype,
      extractedText,
      flags,
      score,
      label,
      hint_en: label === "High Risk" ? "Likely fake or suspicious. Do not trust, verify externally." : (label === "Medium Risk" ? "Potential risk — investigate further." : "Low risk indicators found."),
      hint_hi: label === "High Risk" ? "Jyada shak hai — bharosa na karein, bahar se verify karein." : (label === "Medium Risk" ? "Janch karein — thoda sa shak hai." : "Kuch khas shak nahi mila.")
    });

  } catch (err) {
    console.error(err);
    try { fs.unlinkSync(filePath); } catch(e){}
    res.status(500).json({ error: "Analysis failed" });
  }
});

// Endpoint: Check URL (website)
app.post("/check-url", express.json(), async (req, res) => {
  const { url } = req.body || {};
  if (!url) return res.status(400).json({ error: "No url provided" });
  const flags = [];
  try {
    const parsed = new URL(url);
    const hostname = parsed.hostname;

    // punycode / IDN check
    if (hostname.includes("xn--") || /[^\x00-\x7F]/.test(hostname)) addFlag(flags, "idn", "Domain uses non-ASCII/punycode (possible homograph attack)", 2);

    // suspicious TLDs
    if (/\.(tk|ml|ga|cf|gq)$/.test(hostname)) addFlag(flags, "tld_susp", "Rare/free TLD often used by scammers", 1);

    // fetch page content
    const resp = await axios.get(url, { timeout: 8000, maxRedirects: 3 }).catch(e => null);
    if (!resp || !resp.data) {
      addFlag(flags, "fetch_fail", "Could not fetch page content", 2);
    } else {
      const html = resp.data.toString().slice(0, 200000);
      if (/(password|confirm\s*password|card number|cvv|otp|verify your account)/i.test(html)) addFlag(flags, "asks_credentials", "Page asks for credentials/payment info", 3);
      if (/(<iframe|data:image\/svg\+xml|base64,)/i.test(html)) addFlag(flags, "susp_html", "Hidden iframe / base64 content", 1);
    }

    // WHOIS domain age
    const who = await whois(hostname).catch(()=>null);
    if (who) {
      const created = who.createdDate||who.creationDate||who.created;
      if (created) {
        const c = new Date(created);
        if (!isNaN(c.getTime())) {
          const days = Math.round((Date.now() - c.getTime())/(1000*60*60*24));
          if (days < 30) addFlag(flags, "domain_young", `Domain created ${days} days ago`, 2);
        }
      }
    }

    const { score, label } = computeLabel(flags);
    res.json({ url, flags, score, label, hint_en: label === "High Risk" ? "Avoid, suspicious site." : (label === "Medium Risk" ? "Investigate further." : "Likely safe (not guaranteed).") , hint_hi: label === "High Risk" ? "Nahi kholna — shak hai." : (label === "Medium Risk" ? "Aage janch karein." : "Lagbhag surakshit (poori guarantee nahi).") });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "URL analysis failed" });
  }
});

// Endpoint: Analyze pasted email text (body/headers)
app.post("/analyze-email", express.json(), async (req, res) => {
  const { raw } = req.body || {};
  if (!raw) return res.status(400).json({ error: "No email text provided" });
  const flags = [];
  const text = raw.toString();

  // From/Return-Path mismatch (best-effort pattern)
  const fromMatch = text.match(/^From:\s*(.*)$/im);
  const returnPath = text.match(/^Return-Path:\s*<?([^>\s]+)>?/im);
  if (fromMatch && returnPath) {
    const from = (fromMatch[1]||"").trim();
    const rp = (returnPath[1]||"").trim();
    if (!from.includes(rp.split("@")[1])) addFlag(flags, "from_mismatch", "From header and Return-Path domain mismatch", 2, "Sender headers mismatch may indicate spoofing.");
  }

  if (/urgent|immediately|verify|limited time|click here|reset your password|suspend/i.test(text)) {
    addFlag(flags, "phishy_tone", "Email uses urgent/pressure language", 3, "Typical phishing language found.");
  }

  const linkMatch = text.match(/https?:\/\/[^\s)'"`<>]+/gi) || [];
  if (linkMatch.length) {
    for (const l of linkMatch.slice(0,3)) {
      try {
        const h = new URL(l).hostname;
        const who = await whois(h).catch(()=>null);
        if (who) {
          const created = who.createdDate||who.creationDate||who.created;
          if (created) {
            const days = Math.round((Date.now() - new Date(created).getTime())/(1000*60*60*24));
            if (days < 30) addFlag(flags, "link_new_domain", `Link to young domain (${h})`, 2);
          }
        }
      } catch(e){}
    }
  }

  const { score, label } = computeLabel(flags);
  res.json({ score, label, flags, hint_en: label === "High Risk" ? "Likely phishing — do not click links." : (label === "Medium Risk" ? "Potential phishing." : "Looks okay.") , hint_hi: label === "High Risk" ? "Phishing lagta hai — link na click karein." : (label === "Medium Risk" ? "Sambhavta phishing." : "Thik lagta hai.")});
});

app.listen(PORT, () => {
  console.log(`✅ Fake Document Detector running at http://localhost:${PORT}`);
});
