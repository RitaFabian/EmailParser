# 📧 Automated Email Parser & Organizer

A simple, powerful tool that connects to **Gmail**, fetches your emails, extracts the full message body, categorizes them automatically, and displays useful statistics in an interactive dashboard built with **Python + Streamlit**.

---

## 🚀 Features

### ✔ Fetch Emails

- Connect to **Gmail API**
- Retrieve the full email body, subject, sender, and date
- Decode Gmail Base64 messages automatically

### ✔ Automatic Categorization

- Emails are grouped using custom rules (priority, promotions, billing, etc.)
- Users can modify or extend categorization rules

### ✔ Dashboard Interface

- Built with **Streamlit**
- View all categories
- View total emails per category
- Clean visual stats
- Filter emails

<!-- ### ✔ Data Export

* Export parsed emails to CSV for further analysis -->

### ✔ Fully Python

- Gmail: `google-api-python-client`
- UI: `streamlit`
- Data handling: `pandas`

---

## 🛠️ Tech Stack

| Feature    | Technology |
| ---------- | ---------- |
| UI         | Streamlit  |
| Backend    | Python     |
| Email APIs | Gmail API  |
| Data       | Pandas     |

---

## 📦 Installation

### 1️⃣ Clone the repository

```bash
git clone https://github.com/RitaFabian/EmailParser.git
```

### 2️⃣ Install dependencies

```bash
pip install -r requirements.txt
```

### 3️⃣ Set up API Credentials

### **Gmail API Setup**

1. Go to Google Cloud Console
2. Enable **Gmail API**
3. Create OAuth client
4. Download `credentials.json`
5. Place it in the project folder

---

## 📥 Running the Project

```bash
streamlit run app.py
```

The app will open in your browser automatically.

---

## 🧠 How It Works

### 1. Authenticate the user

- Google: OAuth login

### 2. Fetch emails

- Gmail: `users().messages().list()`

### 3. Extract & decode email body

- Gmail MIME parts decoded from Base64

### 4. Categorize

Examples:

- “invoice”, “receipt” → **Billing**
- “meeting”, “schedule” → **Work**
- “promo”, “offer” → **Promotions**

### 5. Show dashboard

- Total emails
- Emails per category
- Selected email preview

---

## 📊 Dashboard Preview (Description)

- Category list on top
- Email preview panel
- Clean layout optimized for many categories

---

## 📁 Project Structure

```
📦 EmailParser
 ┣ main.py
 ┣ requirements.txt
 ┣ README.md
 ┗ credentials.json (ignored by .gitignore)
```

---

## 🤝 Contributing

Pull requests are welcome!
Open an issue if you'd like new features added.
