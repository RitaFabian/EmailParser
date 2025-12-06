import streamlit as st
import pandas as pd
import re
import os

# This imports are for using the Gmail API and handling Google authentication.
from google.auth.transport.requests import Request
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

# Lets you save Python objects to a file and load them later (used here to store credentials)
import pickle

# For decoding the message body
import base64

# Set up the page
st.set_page_config(page_title="Email Organizer", page_icon="📧", layout="wide")
st.title("📧 Automated Email Parser & Organizer")
st.divider()

# Define what permissions we need from Gmail - here we only ask for read access
SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']

def get_gmail_body(message):
    """Extract the main text content from an email message"""
    payload = message.get("payload", {})
    body = ""

    # Check if the email has multiple parts (like text and attachments)
    if "parts" in payload:
        # Look through each part of the email
        for part in payload["parts"]:
            mime = part.get("mimeType")
            # Get the actual content data
            data = part.get("body", {}).get("data")

            if data and (mime == "text/plain" or mime == "text/html"):
                # Decode the content from base64 format and convert to readable text
                body = base64.urlsafe_b64decode(data).decode("utf-8")
                break

    else:
        # If email is simple and doesn't have multiple parts
        data = payload.get("body", {}).get("data")
        if data:
            body = base64.urlsafe_b64decode(data).decode("utf-8")

    return body

# Connect to Gmail and return the service object that lets us read emails
def get_gmail_service():
    """Connect to Gmail and return the service object that lets us read emails"""
    creds = None
    
    # Check if we have saved credentials from a previous login
    if os.path.exists('token.pickle'):
        # If the token file exists, open it and load our saved credentials
        with open('token.pickle', 'rb') as token:
            creds = pickle.load(token)
    
    # If we don't have valid credentials, let user to log in
    if not creds or not creds.valid:
        # If credentials exist but are expired, try to refresh them
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            # Check if we have the credentials file needed for first-time setup
            if not os.path.exists('credentials.json'):
                # Show an error message if the credentials file is missing
                st.error("""
                **Missing credentials.json file!**
                
                Please download credentials.json from Google Cloud Console
                and make sure it's for a DESKTOP application, not web.
                """)
                return None
            
            try:
                # Start the authentication process
                flow = InstalledAppFlow.from_client_secrets_file('credentials.json', SCOPES)
                creds = flow.run_local_server(port=0)
                
                # Save the credentials for next time so user doesn't have to log in again
                with open('token.pickle', 'wb') as token:
                    pickle.dump(creds, token)
                    
            except Exception as e:
                st.error(f"Authentication failed: {e}")
                return None
    
    # Build and return the Gmail service object that we'll use to read emails
    try:
        service = build('gmail', 'v1', credentials=creds)
        return service
    except Exception as e:
        st.error(f"Failed to create Gmail service: {e}")
        return None

def categorize_email(subject, sender):
    """Simple categorization based on keywords"""
    subject_lower = subject.lower()
    sender_lower = sender.lower()

    # For each category, define a list of keywords and check if any keyword appears in the subject or sender
    # If a match is found, return that category name
    
    # Finance & Banking
    finance_keywords = [
        'moniepoint', 'accessmore', 'bank', 'finance', 'payment',
        'transaction', 'debit', 'credit', 'money'
    ]
    # Check if any finance keyword appears in subject OR sender
    if any(keyword in subject_lower or keyword in sender_lower for keyword in finance_keywords):
        return "Finance & Banking"
    
    # Security & Login Alerts
    security_keywords = [
        'login', 'verification', '2-step', '2fa', 'authenticat', 'access', 'alert',
        'debit alert', 'credit alert', 'successful login', 'security'
    ]
    if any(keyword in subject_lower or keyword in sender_lower for keyword in security_keywords):
        return "Security & Alerts"
    
    # Crypto & Trading
    crypto_keywords = [
        'bybit', 'bitget', 'usdt', 'contract', 'futures', 'trading',
        'airdrop', 'alpha', 'token', 'crypto', 'investment', 'grid'
    ]
    if any(keyword in subject_lower or keyword in sender_lower for keyword in crypto_keywords):
        return "Crypto & Trading"
    
    # Education & Learning
    education_keywords = [
        'assignment', 'test', 'quiz', 'course', 'learning', 'training',
        'material', 'enrolled', 'certificate', 'academy', 'school',
        'psychology', 'design', 'tutorial', 'webinar', 'event'
    ]
    if any(keyword in subject_lower or keyword in sender_lower for keyword in education_keywords):
        return "Education & Learning"
    
    # Career & Jobs
    career_keywords = [
        'career', 'job', 'resume', 'interview', 'fired', 'hired',
        'recruit', 'position', 'role', 'work', 'employee', 'boss',
        'meeting', 'office', 'company', 'technical support', 'economist'
    ]
    if any(keyword in subject_lower or keyword in sender_lower for keyword in career_keywords):
        return "Career & Jobs"
    
    # News & Updates
    news_keywords = [
        'breaking', 'news', 'update', 'alert', 'turkey', 'israel',
        'relations', 'official', 'notification', 'announcement'
    ]
    if any(keyword in subject_lower or keyword in sender_lower for keyword in news_keywords):
        return "News & Updates"
    
    # Technology & Development
    tech_keywords = [
        'github', 'run failed', 'autograding', 'pr run', 'python',
        'api', 'gpt', 'openai', 'code', 'programming', 'developer',
        'hackathon', 'cybersecurity', 'ethical hacker', 'technical'
    ]
    if any(keyword in subject_lower or keyword in sender_lower for keyword in tech_keywords):
        return "Technology & Development"
    
    # Promotions & Sales
    promo_keywords = [
        'sale', 'discount', 'offer', 'black friday', 'christmas',
        'exclusive', 'win', 'free', 'reward', 'bonus', 'airdrop',
        'leaderboard', 'pool', 'protection', 'boost'
    ]
    if any(keyword in subject_lower or keyword in sender_lower for keyword in promo_keywords):
        return "Promotions & Sales"
    
    # Design & Creativity
    design_keywords = [
        'design', 'canva', 'figma', 'layout', 'component', 'variant',
        'instance', 'mobbin', 'animation', 'creator', 'creative'
    ]
    if any(keyword in subject_lower or keyword in sender_lower for keyword in design_keywords):
        return "Design & Creativity"
    
    # Personal Development
    personal_keywords = [
        'personal', 'development', 'growth', 'mindset', 'investment',
        'career advice', 'tips', 'guide', 'how to', 'lesson', 'vibe',
        'inspiration', 'motivation', 'story', 'haters', 'burnout'
    ]
    if any(keyword in subject_lower or keyword in sender_lower for keyword in personal_keywords):
        return "Personal Development"
    
    # Social & Networking
    social_keywords = [
        'contact', 'endorse', 'connect', 'network', 'invite', 'join',
        'event', 'webinar', 'meetup', 'community'
    ]
    if any(keyword in subject_lower or keyword in sender_lower for keyword in social_keywords):
        return "Social & Networking"
    
    # If no other category matches, put it in "Other"
    return "Other"

# Extract email data from Gmail and categorize them
def extract_email_data(service, max_results=50):
    """Get emails from Gmail and extract useful information from them"""
    try:
        # Get list of messages (this returns message IDs, not full messages)
        results = service.users().messages().list(
            userId='me', 
            maxResults=max_results # How many emails to get
        ).execute()
        messages = results.get('messages', [])

        # An empty list to store processed email data
        email_data = []
        
        # Loop through each message ID we got and process it
        for message in messages:
            # Get the full email data using the message ID
            msg = service.users().messages().get(
                userId='me', 
                id=message['id'],
                format="full"
            ).execute()
            
            # Extract headers like Subject, From, Date from the email
            headers = msg['payload'].get('headers', [])
            subject = next((h['value'] for h in headers if h['name'] == 'Subject'), 'No Subject')
            sender = next((h['value'] for h in headers if h['name'] == 'From'), 'Unknown Sender')
            date = next((h['value'] for h in headers if h['name'] == 'Date'), 'Unknown Date')
            
            # snippet = msg.get('snippet', 'No content')
            # Extract the main body text of the email
            snippet = get_gmail_body(msg) or 'No content'
            
            # Categorize email
            category = categorize_email(subject, sender)
            
            # Extract just the email address from sender (remove display name)
            email_match = re.search(r'<(.+?)>', sender)
            if email_match:
                sender_email = email_match.group(1)
            else:
                sender_email = sender
            
            # Add all this information to our email data list
            email_data.append({
                'id': message['id'],
                'subject': subject,
                'sender': sender_email,
                'date': date,
                'snippet': snippet,
                'category': category
            })
            
        # Return the list of processed emails
        return email_data
        
    except HttpError as error:
        st.error(f"An error occurred: {error}")
        return []

def main():
    # Sidebar for controls
    st.sidebar.title("Controls")
    
    # Authentication section
    st.sidebar.subheader("Authentication")
    
    # Check if we're already connected to Gmail
    if 'service' not in st.session_state:
        # Show connect button if not connected
        if st.sidebar.button("Connect to Gmail"):
            with st.spinner("Connecting to Gmail..."):
                service = get_gmail_service()
                if service:
                    # Save the service object in session state for later use
                    st.session_state.service = service
                    st.sidebar.success("Connected to Gmail!")
                else:
                    st.sidebar.error("Failed to connect. Please check your credentials.")
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               
    # Email fetching - only show these controls if we're connected to Gmail
    if 'service' in st.session_state:                                                        
        st.sidebar.subheader("Email Settings")
        # Let user choose how many emails to fetch (between 10 and 100)
        email_count = st.sidebar.number_input("Number of emails to fetch", 10, 100, 50)
        
        # Button to actually fetch the emails
        if st.sidebar.button("Fetch Emails"):
            with st.spinner("Fetching emails..."):
                emails = extract_email_data(st.session_state.service, email_count)
                if emails:
                    # Save the fetched emails in session state
                    st.session_state.emails = emails
                    st.sidebar.success(f"Fetched {len(emails)} emails!")
                else:
                    st.sidebar.error("No emails found or error fetching emails")
    
    # Main content area
    if 'emails' not in st.session_state:
        # Show instructions if no emails have been fetched yet
        st.info("👈 Connect to Gmail and fetch emails to get started!")
        
        # Show sample data for demonstration
        st.subheader("Sample Data Preview")
        sample_data = [
            {
                'subject': 'Weekly Team Meeting',
                'sender': 'boss@company.com',
                'category': 'Work',
                'snippet': 'Hi team, reminder about our weekly meeting tomorrow...'
            },
            {
                'subject': 'Family Dinner Plans',
                'sender': 'mom@family.com',
                'category': 'Personal',
                'snippet': 'Hey, are you coming for dinner this weekend?'
            },
            {
                'subject': '50% OFF Summer Sale!',
                'sender': 'store@promotions.com',
                'category': 'Promotions',
                'snippet': 'Don\'t miss our amazing summer sale...'
            }
        ]
        
        # Convert sample data to a pandas DataFrame and display as a table
        df_sample = pd.DataFrame(sample_data)
        st.dataframe(df_sample)
        
    else:
        # Display organized emails
        emails = st.session_state.emails
        # Convert emails data to a pandas DataFrame for easier manipulation
        df = pd.DataFrame(emails)
        
        # Statistics
        st.subheader("📊 Email Overview")
        categories = ['All'] + sorted(df['category'].unique().tolist())

        # Calculate stats
        total_emails = len(emails)
        # Count how many emails are in each category
        category_counts = df['category'].value_counts()

        # Create three columns for displaying metrics
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("Total Emails", total_emails)
        with col2:
            st.metric("Total Categories", len(category_counts))
        with col3:
            # Show the most common category and how many emails it has
            top_category = category_counts.index[0]
            top_count = category_counts.iloc[0]
            st.metric("Most Common", top_category, delta=f"{top_count} emails")

        # Show categories in a compact expander
        with st.expander(f"📂 View All Categories ({len(category_counts)})"):
            cols = st.columns(3)
            
            # Loop through each category and display its count and percentage
            for idx, (category, count) in enumerate(category_counts.items()):
                # Calculate percentage
                percentage = (count / total_emails) * 100
                with cols[idx % 3]:
                    st.metric(
                        label=category,
                        value=count,
                        delta=f"{percentage:.1f}%"
                    )

        # Category filter
        st.subheader("📂 Browse by Category")
        # Create a dropdown to select which category to view
        selected_category = st.selectbox("Choose a category:", categories)
        
        # Filter the emails based on selected category
        if selected_category != 'All':
            filtered_df = df[df['category'] == selected_category]
        else:
            filtered_df = df
        
        # Display emails
        st.subheader(f"📨 Emails ({selected_category})")
        
        # Loop through each email in the filtered list
        for _, email in filtered_df.iterrows():
            # Create an expandable section for each email
            with st.expander(f"{email['subject']} - {email['sender']}"):
                col1, col2 = st.columns([3, 1])
                
                with col1:
                    st.write(f"**From:** {email['sender']}")
                    st.write(f"**Date:** {email['date']}")
                    # st.write(f"**Preview:** {email['snippet']}")
                    st.markdown(f"**Preview:** {email['snippet']}", unsafe_allow_html=True)

                
                with col2:
                    st.write(f"**Category:** {email['category']}")
                    # if st.button("View", key=email['id']):
                    #     st.info("Full email view would go here (requires additional implementation)")
        
        # Show raw data as a table
        if st.checkbox("Show As table"):
            st.subheader("Raw Email Data")
            st.dataframe(df)

# This line runs the main function when the script is executed directly
if __name__ == "__main__":
    main()
