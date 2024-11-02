# Email Classifier

## Description

This Python script leverages the Gmail and OpenAI APIs to classify emails as *Malicious* or *Benign*. It specifically targets emails labeled as "purchases/orders" and uses a cybersecurity-focused language model prompt to identify phishing, spam, or legitimate content.

## Features

- **Label Filtering**: Reads emails labeled as "purchases/orders".
- **Classification**: Analyzes email content for malicious intent using an OpenAI-powered model.
- **Automated Workflow**: Integrates with Gmail API for automated email retrieval and classification.

## Requirements

- Python 3.7+
- Google Gmail API credentials
- OpenAI API key
- Packages:
  - `google-auth`, `google-auth-oauthlib`, `google-auth-httplib2`, `google-api-python-client`
  - `openai`

## Setup

1. **Gmail API Setup**:
   - Enable the Gmail API on [Google Cloud Console](https://console.cloud.google.com/).
   - Download OAuth 2.0 credentials as a JSON file and save it to `/content/drive/MyDrive/Api-keys/credentials.json`.

2. **OpenAI API Key**:
   - Obtain an API key from [OpenAI](https://platform.openai.com/).
   - Save the key in `/content/drive/MyDrive/Api-keys/openai_key.txt`.

3. **Install Dependencies**:
   ```bash
   pip install google-auth google-auth-oauthlib google-auth-httplib2 google-api-python-client openai
