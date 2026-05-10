const fs = require('fs')
const path = require('path')

const ROOT = path.resolve(__dirname, '..')
const OUT_DIR = path.join(ROOT, 'docs')
const OUT_FILE = path.join(OUT_DIR, 'Phishing_Autopsy_Minor_Project_Report.docx')

const sections = [
  { type: 'title', text: 'Phishing Autopsy' },
  { type: 'subtitle', text: 'A Local Email Threat Analysis and Phishing Detection System' },
  { type: 'center', text: 'Report submitted in partial fulfillment of the requirements for the degree of' },
  { type: 'centerBold', text: 'Master of Computer Applications (MCA)' },
  { type: 'center', text: 'by' },
  { type: 'centerBold', text: 'Prashant Prasad' },
  { type: 'center', text: 'Roll No: 011-MCA-2024-043' },
  { type: 'center', text: 'Under the guidance of' },
  { type: 'centerBold', text: 'Prof. Sanjay Nag' },
  { type: 'center', text: 'MCA [2024 - 2026]' },
  { type: 'pagebreak' },

  { type: 'heading1', text: 'ACKNOWLEDGEMENT' },
  { type: 'p', text: 'I would like to express my sincere gratitude to Prof. Sanjay Nag for his valuable guidance, encouragement, and support throughout the development of this minor project, "Phishing Autopsy". His direction helped shape the project into a practical cybersecurity analysis tool with a clear technical workflow and demonstrable outcomes.' },
  { type: 'p', text: 'I am also thankful to my classmates and peers for their feedback during testing and demonstration preparation. Their suggestions helped improve the usability of the frontend analyst console, the clarity of the generated risk factors, and the quality of the test cases used to verify system integrity.' },
  { type: 'p', text: 'Finally, I would like to acknowledge the open-source tools, datasets, and documentation that supported the implementation of the machine-learning pipeline, backend API, and frontend user interface.' },
  { type: 'pagebreak' },

  { type: 'heading1', text: 'CERTIFICATE' },
  { type: 'p', text: 'This is to certify that the project titled "Phishing Autopsy: A Local Email Threat Analysis and Phishing Detection System" submitted in partial fulfillment of the requirements for the degree of Master of Computer Applications (MCA) is an authentic work carried out by Prashant Prasad under my guidance.' },
  { type: 'p', text: 'The matter embodied in this project report has not been submitted earlier for the award of any degree or diploma to the best of my knowledge and belief.' },
  { type: 'blank', count: 3 },
  { type: 'p', text: 'Date: ____________________' },
  { type: 'p', text: 'Signature of the Guide: ____________________' },
  { type: 'p', text: 'Prof. Sanjay Nag' },
  { type: 'pagebreak' },

  { type: 'heading1', text: 'CONTENT' },
  { type: 'toc', text: '1. Abstract' },
  { type: 'toc', text: '2. Introduction' },
  { type: 'tocSub', text: 'Objectives' },
  { type: 'tocSub', text: 'Scope' },
  { type: 'tocSub', text: 'Challenges' },
  { type: 'toc', text: '3. Libraries and Tools Used' },
  { type: 'toc', text: '4. Methodology' },
  { type: 'tocSub', text: 'Data Collection' },
  { type: 'tocSub', text: 'Data Preprocessing' },
  { type: 'tocSub', text: 'Feature Extraction' },
  { type: 'tocSub', text: 'Model Training' },
  { type: 'tocSub', text: 'Real-Time Implementation' },
  { type: 'toc', text: '5. Results' },
  { type: 'tocSub', text: 'Regression Test Cases' },
  { type: 'tocSub', text: 'Example Outputs' },
  { type: 'toc', text: '6. Conclusion' },
  { type: 'tocSub', text: 'Key Findings' },
  { type: 'tocSub', text: 'Future Work' },
  { type: 'toc', text: '7. References' },
  { type: 'toc', text: '8. Appendices' },
  { type: 'pagebreak' },

  { type: 'heading1', text: '1. ABSTRACT' },
  { type: 'p', text: 'This project focuses on developing a local phishing email analysis system capable of inspecting suspicious email messages and identifying phishing indicators using both machine-learning and rule-based techniques. The system accepts raw .eml files or manually pasted email text and produces an analyst-oriented report containing a threat score, verdict, DNS checks, header analysis, URL intelligence, language-based risk factors, and attachment evidence.' },
  { type: 'p', text: 'The backend is implemented using Flask and integrates a trained TF-IDF based text classifier with additional heuristic analysis. The classifier estimates phishing probability from email body content, while the heuristic layer evaluates practical threat indicators such as Reply-To mismatch, Return-Path mismatch, MX/SPF/DMARC record presence, suspicious links, URL shorteners, IP-address based URLs, credential-harvesting language, financial pressure, and business email compromise patterns.' },
  { type: 'p', text: 'The frontend is built with React and Vite and presents the result in a technical analyst console. The interface helps users understand why an email was classified as low-risk, suspicious, or high-risk. The system also includes synthetic real-world test cases to verify integrity before demonstration. This makes the project suitable for learning, experimentation, and academic demonstration of phishing detection concepts.' },

  { type: 'heading1', text: '2. INTRODUCTION' },
  { type: 'p', text: 'Phishing remains one of the most common cybersecurity threats because attackers use deceptive email messages to steal credentials, initiate fraudulent payments, deliver malware, or impersonate trusted organizations. Unlike ordinary spam, phishing emails often combine social engineering, urgency, brand impersonation, malicious links, and header manipulation to convince users to act quickly.' },
  { type: 'p', text: 'The goal of Phishing Autopsy is to provide a local analysis environment where suspicious emails can be examined in a transparent and explainable manner. Instead of only returning a single prediction, the system exposes the evidence behind the decision so that a user can understand the reason for the classification.' },
  { type: 'heading2', text: 'Objectives' },
  { type: 'bullet', text: 'Develop a local email analysis system for suspicious .eml files and pasted email text.' },
  { type: 'bullet', text: 'Train and use a machine-learning model for phishing probability estimation.' },
  { type: 'bullet', text: 'Extract technical email indicators from headers, sender domains, links, body text, and attachments.' },
  { type: 'bullet', text: 'Generate explainable risk factors for phishing, credential theft, and business email compromise patterns.' },
  { type: 'bullet', text: 'Create a frontend analyst console for clear visualization of threat evidence.' },
  { type: 'heading2', text: 'Scope' },
  { type: 'p', text: 'The project focuses on local analysis of email samples and direct text input. It supports .eml parsing, text classification, DNS record checks, URL analysis, header mismatch detection, attachment metadata detection, and synthetic regression testing. It is intended for academic demonstration and learning rather than production email filtering.' },
  { type: 'heading2', text: 'Challenges' },
  { type: 'bullet', text: 'Phishing emails vary widely in wording, format, and sender infrastructure.' },
  { type: 'bullet', text: 'Legitimate domains may lack some DNS records, so DNS must be treated as supporting evidence rather than absolute proof.' },
  { type: 'bullet', text: 'HTML emails can hide URLs inside href attributes, requiring raw HTML link extraction.' },
  { type: 'bullet', text: 'A model trained only on spam data may confuse spam and phishing, so phishing-oriented datasets and heuristics are needed.' },
  { type: 'bullet', text: 'The frontend must handle evolving backend response structures without crashing.' },

  { type: 'heading1', text: '3. LIBRARIES AND TOOLS USED' },
  { type: 'heading2', text: 'Python' },
  { type: 'p', text: 'Python is used for the backend API, email parsing, DNS checks, model loading, and training pipeline. It provides strong library support for text processing and machine learning.' },
  { type: 'heading2', text: 'Flask and Flask-CORS' },
  { type: 'p', text: 'Flask provides the REST API endpoint /api/analyze. Flask-CORS allows the React frontend running on the Vite development server to communicate with the backend during local development.' },
  { type: 'heading2', text: 'scikit-learn' },
  { type: 'p', text: 'scikit-learn is used for TF-IDF vectorization and the phishing classification model. The model estimates the probability that an email belongs to the phishing or spam class.' },
  { type: 'heading2', text: 'pandas and joblib' },
  { type: 'p', text: 'pandas supports dataset loading and normalization during training. joblib is used to save and load the trained model and vectorizer artifacts.' },
  { type: 'heading2', text: 'dnspython' },
  { type: 'p', text: 'dnspython performs MX, SPF, and DMARC record lookups to evaluate sender-domain posture.' },
  { type: 'heading2', text: 'React, Vite, and Axios' },
  { type: 'p', text: 'React powers the frontend analyst console. Vite provides fast local development and production builds. Axios handles HTTP requests from the frontend to the Flask backend.' },

  { type: 'heading1', text: '4. METHODOLOGY' },
  { type: 'heading2', text: 'Data Collection' },
  { type: 'p', text: 'The original Kaggle spam email classification dataset was retained and moved into backend/datasets. Additional phishing-oriented datasets were added, including CSV files with structures such as label,text; text_combined,label; subject,body,label; and subject,body,urls,label.' },
  { type: 'heading2', text: 'Data Preprocessing' },
  { type: 'bullet', text: 'Load all supported CSV files from backend/datasets.' },
  { type: 'bullet', text: 'Normalize labels into 0 for legitimate/ham/safe and 1 for phishing/spam/scam/malicious.' },
  { type: 'bullet', text: 'Combine subject, body, and URL columns when required.' },
  { type: 'bullet', text: 'Remove missing values, very short text rows, and duplicate email text.' },
  { type: 'heading2', text: 'Feature Extraction' },
  { type: 'p', text: 'Text features are extracted using TF-IDF vectorization with unigrams and bigrams. This helps capture individual words as well as short phrases commonly found in phishing emails, such as password verification, urgent payment, account suspension, and final notice.' },
  { type: 'heading2', text: 'Model Training' },
  { type: 'p', text: 'The training script performs a stratified train/test split and trains a Naive Bayes-style classifier. The resulting phishing_model.pkl and vectorizer.pkl files are loaded by the Flask backend during analysis.' },
  { type: 'heading2', text: 'Real-Time Implementation' },
  { type: 'bullet', text: 'User uploads an .eml file or enters email text manually.' },
  { type: 'bullet', text: 'Backend parses headers, body, HTML content, URLs, and attachments.' },
  { type: 'bullet', text: 'The ML model calculates phishing probability from body text.' },
  { type: 'bullet', text: 'The heuristic engine generates risk factors for DNS, headers, links, language, and attachments.' },
  { type: 'bullet', text: 'The frontend displays final score, verdict, evidence cards, and prioritized findings.' },

  { type: 'heading1', text: '5. RESULTS' },
  { type: 'p', text: 'The system was verified using synthetic real-world style .eml fixtures. These fixtures cover benign messages and multiple phishing categories such as credential harvesting, CEO payment fraud, Reply-To mismatch, URL shortener abuse, invoice attachment lure, HTML brand impersonation, IP-address login lure, and multi-domain tracking lure.' },
  { type: 'heading2', text: 'Regression Test Cases' },
  { type: 'bullet', text: 'benign_vendor_update: low risk.' },
  { type: 'bullet', text: 'credential_harvest: high risk with link and credential language evidence.' },
  { type: 'bullet', text: 'ceo_payment_fraud: high risk with business email compromise language.' },
  { type: 'bullet', text: 'reply_to_mismatch: high risk with header mismatch evidence.' },
  { type: 'bullet', text: 'url_shortener_lure: high risk with URL shortener evidence.' },
  { type: 'bullet', text: 'invoice_attachment_lure: high risk with attachment and payment-lure evidence.' },
  { type: 'bullet', text: 'html_brand_impersonation: high risk with HTML href extraction and suspicious URL evidence.' },
  { type: 'bullet', text: 'benign_newsletter: low risk.' },
  { type: 'bullet', text: 'ip_address_login_lure: high risk with IP-address URL evidence.' },
  { type: 'bullet', text: 'multi_domain_tracking_lure: high risk with multiple domain and verification-lure evidence.' },
  { type: 'bullet', text: 'benign_internal_build_report: low risk.' },
  { type: 'heading2', text: 'Example Outputs' },
  { type: 'p', text: 'For high-risk samples, the frontend displays a high score along with evidence such as suspicious URL pattern, credential lure language, business email compromise pattern, Reply-To mismatch, and attachment presence. For benign samples, DNS-only issues from example domains are shown as supporting evidence but do not force a high-risk verdict.' },

  { type: 'heading1', text: '6. CONCLUSION' },
  { type: 'heading2', text: 'Key Findings' },
  { type: 'bullet', text: 'Combining machine learning with heuristic evidence produces more explainable results than a model-only score.' },
  { type: 'bullet', text: 'DNS record absence should be treated as supporting evidence, not an automatic phishing verdict.' },
  { type: 'bullet', text: 'Header mismatches and URL patterns are strong practical indicators during email analysis.' },
  { type: 'bullet', text: 'A structured frontend helps users understand the reason behind each verdict.' },
  { type: 'heading2', text: 'Future Work' },
  { type: 'bullet', text: 'Add DKIM validation and stronger SPF/DMARC alignment checks from Authentication-Results headers.' },
  { type: 'bullet', text: 'Integrate safe URL reputation lookups and redirect-chain analysis.' },
  { type: 'bullet', text: 'Improve model calibration using a larger phishing-specific dataset.' },
  { type: 'bullet', text: 'Add exportable PDF/HTML analysis reports for individual emails.' },
  { type: 'bullet', text: 'Add authentication, rate limiting, logging, and deployment configuration for production use.' },

  { type: 'heading1', text: '7. REFERENCES' },
  { type: 'bullet', text: 'Kaggle Spam Email Classification Dataset.' },
  { type: 'bullet', text: 'Public phishing email datasets used for local training and experimentation.' },
  { type: 'bullet', text: 'Flask documentation for API development.' },
  { type: 'bullet', text: 'scikit-learn documentation for TF-IDF vectorization and Naive Bayes classification.' },
  { type: 'bullet', text: 'dnspython documentation for DNS record lookups.' },
  { type: 'bullet', text: 'React and Vite documentation for frontend development.' },

  { type: 'heading1', text: '8. APPENDICES' },
  { type: 'heading2', text: 'Appendix A: Important Commands' },
  { type: 'code', text: 'cd backend\npython app.py\npython run_test_cases.py\npython train_model.py' },
  { type: 'code', text: 'cd frontend\nnpm install\nnpm run dev\nnpm run build\nnpm run lint' },
  { type: 'heading2', text: 'Appendix B: Demo Email Samples' },
  { type: 'p', text: 'Manual demonstration samples are stored in backend/test_emails. Regression fixtures and expectations are stored in backend/test_cases.' },
  { type: 'heading2', text: 'Appendix C: Project Report Generation' },
  { type: 'code', text: 'node scripts/generate_project_report_docx.js' },
]

function escapeXml(value) {
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;')
}

function run(text, opts = {}) {
  const props = [
    opts.bold ? '<w:b/>' : '',
    opts.italic ? '<w:i/>' : '',
    opts.size ? `<w:sz w:val="${opts.size}"/>` : '',
  ].join('')
  return `<w:r>${props ? `<w:rPr>${props}</w:rPr>` : ''}<w:t xml:space="preserve">${escapeXml(text)}</w:t></w:r>`
}

function paragraph(item) {
  if (item.type === 'pagebreak') return '<w:p><w:r><w:br w:type="page"/></w:r></w:p>'
  if (item.type === 'blank') return Array.from({ length: item.count }, () => '<w:p/>').join('')

  const styleMap = {
    title: 'Title',
    subtitle: 'Subtitle',
    heading1: 'Heading1',
    heading2: 'Heading2',
    code: 'Code',
  }
  const style = styleMap[item.type]
  const bullet = item.type === 'bullet'
  const center = ['title', 'subtitle', 'center', 'centerBold'].includes(item.type)
  const toc = ['toc', 'tocSub'].includes(item.type)
  const pPr = [
    style ? `<w:pStyle w:val="${style}"/>` : '',
    bullet ? '<w:numPr><w:ilvl w:val="0"/><w:numId w:val="1"/></w:numPr>' : '',
    center ? '<w:jc w:val="center"/>' : '',
    toc ? '<w:tabs><w:tab w:val="right" w:leader="dot" w:pos="9000"/></w:tabs>' : '',
    item.type === 'tocSub' ? '<w:ind w:left="720"/>' : '',
  ].join('')

  const lines = String(item.text).split('\n')
  const body = lines.map((line, index) => `${index ? '<w:br/>' : ''}${run(line, {
    bold: item.type === 'centerBold',
    size: item.type === 'centerBold' ? 24 : undefined,
  })}`).join('')
  return `<w:p>${pPr ? `<w:pPr>${pPr}</w:pPr>` : ''}${body}</w:p>`
}

function documentXml() {
  return `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
  <w:body>
    ${sections.map(paragraph).join('\n')}
    <w:sectPr>
      <w:pgSz w:w="12240" w:h="15840"/>
      <w:pgMar w:top="1080" w:right="1080" w:bottom="1080" w:left="1080"/>
    </w:sectPr>
  </w:body>
</w:document>`
}

const files = {
  '[Content_Types].xml': `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
  <Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
  <Override PartName="/word/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml"/>
  <Override PartName="/word/numbering.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.numbering+xml"/>
</Types>`,
  '_rels/.rels': `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>
</Relationships>`,
  'word/document.xml': documentXml(),
  'word/styles.xml': `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:styles xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
  <w:style w:type="paragraph" w:default="1" w:styleId="Normal"><w:name w:val="Normal"/><w:pPr><w:spacing w:after="160"/></w:pPr><w:rPr><w:sz w:val="24"/></w:rPr></w:style>
  <w:style w:type="paragraph" w:styleId="Title"><w:name w:val="Title"/><w:pPr><w:jc w:val="center"/><w:spacing w:before="1200" w:after="360"/></w:pPr><w:rPr><w:b/><w:sz w:val="44"/></w:rPr></w:style>
  <w:style w:type="paragraph" w:styleId="Subtitle"><w:name w:val="Subtitle"/><w:pPr><w:jc w:val="center"/><w:spacing w:after="720"/></w:pPr><w:rPr><w:i/><w:sz w:val="28"/></w:rPr></w:style>
  <w:style w:type="paragraph" w:styleId="Heading1"><w:name w:val="heading 1"/><w:basedOn w:val="Normal"/><w:next w:val="Normal"/><w:pPr><w:spacing w:before="360" w:after="220"/></w:pPr><w:rPr><w:b/><w:sz w:val="30"/></w:rPr></w:style>
  <w:style w:type="paragraph" w:styleId="Heading2"><w:name w:val="heading 2"/><w:basedOn w:val="Normal"/><w:next w:val="Normal"/><w:pPr><w:spacing w:before="240" w:after="160"/></w:pPr><w:rPr><w:b/><w:sz w:val="26"/></w:rPr></w:style>
  <w:style w:type="paragraph" w:styleId="Code"><w:name w:val="Code"/><w:pPr><w:spacing w:before="120" w:after="120"/></w:pPr><w:rPr><w:rFonts w:ascii="Consolas" w:hAnsi="Consolas"/><w:sz w:val="20"/></w:rPr></w:style>
</w:styles>`,
  'word/numbering.xml': `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:numbering xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
  <w:abstractNum w:abstractNumId="0">
    <w:lvl w:ilvl="0"><w:start w:val="1"/><w:numFmt w:val="bullet"/><w:lvlText w:val="-"/><w:lvlJc w:val="left"/><w:pPr><w:ind w:left="720" w:hanging="360"/></w:pPr></w:lvl>
  </w:abstractNum>
  <w:num w:numId="1"><w:abstractNumId w:val="0"/></w:num>
</w:numbering>`,
}

const crcTable = new Uint32Array(256)
for (let n = 0; n < 256; n += 1) {
  let c = n
  for (let k = 0; k < 8; k += 1) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1
  crcTable[n] = c >>> 0
}

function crc32(buffer) {
  let c = 0xffffffff
  for (const byte of buffer) c = crcTable[(c ^ byte) & 0xff] ^ (c >>> 8)
  return (c ^ 0xffffffff) >>> 0
}

function dosTimeDate(date) {
  const time = (date.getHours() << 11) | (date.getMinutes() << 5) | Math.floor(date.getSeconds() / 2)
  const day = date.getDate()
  const month = date.getMonth() + 1
  const year = Math.max(1980, date.getFullYear()) - 1980
  return { time, date: (year << 9) | (month << 5) | day }
}

function u16(value) {
  const b = Buffer.alloc(2)
  b.writeUInt16LE(value)
  return b
}

function u32(value) {
  const b = Buffer.alloc(4)
  b.writeUInt32LE(value >>> 0)
  return b
}

function createZip(entries) {
  const now = dosTimeDate(new Date())
  const localParts = []
  const centralParts = []
  let offset = 0

  for (const [name, content] of Object.entries(entries)) {
    const nameBuffer = Buffer.from(name)
    const data = Buffer.from(content, 'utf8')
    const crc = crc32(data)
    const localHeader = Buffer.concat([
      u32(0x04034b50), u16(20), u16(0), u16(0), u16(now.time), u16(now.date),
      u32(crc), u32(data.length), u32(data.length), u16(nameBuffer.length), u16(0), nameBuffer,
    ])
    localParts.push(localHeader, data)

    const centralHeader = Buffer.concat([
      u32(0x02014b50), u16(20), u16(20), u16(0), u16(0), u16(now.time), u16(now.date),
      u32(crc), u32(data.length), u32(data.length), u16(nameBuffer.length), u16(0), u16(0),
      u16(0), u16(0), u32(0), u32(offset), nameBuffer,
    ])
    centralParts.push(centralHeader)
    offset += localHeader.length + data.length
  }

  const central = Buffer.concat(centralParts)
  const end = Buffer.concat([
    u32(0x06054b50), u16(0), u16(0), u16(Object.keys(entries).length), u16(Object.keys(entries).length),
    u32(central.length), u32(offset), u16(0),
  ])

  return Buffer.concat([...localParts, central, end])
}

fs.mkdirSync(OUT_DIR, { recursive: true })
fs.writeFileSync(OUT_FILE, createZip(files))
console.log(OUT_FILE)
