{
  "nbformat": 4,
  "nbformat_minor": 0,
  "metadata": {
    "colab": {
      "provenance": [],
      "mount_file_id": "1LSSMbdRev2saaQRDwc1u0qdE_GPvd7Y6",
      "authorship_tag": "ABX9TyO3xdm6vS3REddqeQ+/ZHAs",
      "include_colab_link": true
    },
    "kernelspec": {
      "name": "python3",
      "display_name": "Python 3"
    },
    "language_info": {
      "name": "python"
    }
  },
  "cells": [
    {
      "cell_type": "markdown",
      "metadata": {
        "id": "view-in-github",
        "colab_type": "text"
      },
      "source": [
        "<a href=\"https://colab.research.google.com/github/SF1308/email-detector/blob/main/Detecci%C3%B3n_de_correos_maliciosos_con_ChatGPT.ipynb\" target=\"_parent\"><img src=\"https://colab.research.google.com/assets/colab-badge.svg\" alt=\"Open In Colab\"/></a>"
      ]
    },
    {
      "cell_type": "code",
      "source": [
        "# Ensure the latest OpenAI library version is installed\n",
        "!pip install --upgrade openai"
      ],
      "metadata": {
        "colab": {
          "base_uri": "https://localhost:8080/"
        },
        "id": "Ei3BwH4N34-G",
        "outputId": "b5e61308-7777-4aa4-9731-5b53eadb8979"
      },
      "execution_count": null,
      "outputs": [
        {
          "output_type": "stream",
          "name": "stdout",
          "text": [
            "Requirement already satisfied: openai in /usr/local/lib/python3.10/dist-packages (1.53.0)\n",
            "Requirement already satisfied: anyio<5,>=3.5.0 in /usr/local/lib/python3.10/dist-packages (from openai) (3.7.1)\n",
            "Requirement already satisfied: distro<2,>=1.7.0 in /usr/local/lib/python3.10/dist-packages (from openai) (1.9.0)\n",
            "Requirement already satisfied: httpx<1,>=0.23.0 in /usr/local/lib/python3.10/dist-packages (from openai) (0.27.2)\n",
            "Requirement already satisfied: jiter<1,>=0.4.0 in /usr/local/lib/python3.10/dist-packages (from openai) (0.6.1)\n",
            "Requirement already satisfied: pydantic<3,>=1.9.0 in /usr/local/lib/python3.10/dist-packages (from openai) (2.9.2)\n",
            "Requirement already satisfied: sniffio in /usr/local/lib/python3.10/dist-packages (from openai) (1.3.1)\n",
            "Requirement already satisfied: tqdm>4 in /usr/local/lib/python3.10/dist-packages (from openai) (4.66.5)\n",
            "Requirement already satisfied: typing-extensions<5,>=4.11 in /usr/local/lib/python3.10/dist-packages (from openai) (4.12.2)\n",
            "Requirement already satisfied: idna>=2.8 in /usr/local/lib/python3.10/dist-packages (from anyio<5,>=3.5.0->openai) (3.10)\n",
            "Requirement already satisfied: exceptiongroup in /usr/local/lib/python3.10/dist-packages (from anyio<5,>=3.5.0->openai) (1.2.2)\n",
            "Requirement already satisfied: certifi in /usr/local/lib/python3.10/dist-packages (from httpx<1,>=0.23.0->openai) (2024.8.30)\n",
            "Requirement already satisfied: httpcore==1.* in /usr/local/lib/python3.10/dist-packages (from httpx<1,>=0.23.0->openai) (1.0.6)\n",
            "Requirement already satisfied: h11<0.15,>=0.13 in /usr/local/lib/python3.10/dist-packages (from httpcore==1.*->httpx<1,>=0.23.0->openai) (0.14.0)\n",
            "Requirement already satisfied: annotated-types>=0.6.0 in /usr/local/lib/python3.10/dist-packages (from pydantic<3,>=1.9.0->openai) (0.7.0)\n",
            "Requirement already satisfied: pydantic-core==2.23.4 in /usr/local/lib/python3.10/dist-packages (from pydantic<3,>=1.9.0->openai) (2.23.4)\n"
          ]
        }
      ]
    },
    {
      "cell_type": "markdown",
      "source": [
        " 1 Configuración de la API Key de OpenAI"
      ],
      "metadata": {
        "id": "YXYHtSday2HE"
      }
    },
    {
      "cell_type": "code",
      "execution_count": null,
      "metadata": {
        "id": "yp6mqk4hazdU"
      },
      "outputs": [],
      "source": [
        "# Step 1. Configuring the OpenAI API Key\n",
        "\n",
        "import os\n",
        "\n",
        "# Load the API key from a secure location, such as Google Drive, and set it in the environment\n",
        "with open(\"{{your_openAI_api_key}}\") as f:\n",
        "    os.environ[\"OPENAI_API_KEY\"] = f.readline().strip()"
      ]
    },
    {
      "cell_type": "code",
      "source": [
        "print(os.environ[\"OPENAI_API_KEY\"])"
      ],
      "metadata": {
        "colab": {
          "base_uri": "https://localhost:8080/"
        },
        "id": "xIW2Jxniy1KC",
        "outputId": "24b78e33-fa9a-4e3c-ba11-bfcfa6318266"
      },
      "execution_count": null,
      "outputs": [
        {
          "output_type": "stream",
          "name": "stdout",
          "text": [
            "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\n"
          ]
        }
      ]
    },
    {
      "cell_type": "markdown",
      "source": [
        "# 2. Email classification function with ICL"
      ],
      "metadata": {
        "id": "ObjV7bgszQOa"
      }
    },
    {
      "cell_type": "code",
      "source": [
        "import os\n",
        "from openai import OpenAI\n",
        "\n",
        "# Initialize the OpenAI client with the API key\n",
        "client = OpenAI(api_key=os.environ.get(\"OPENAI_API_KEY\"))\n",
        "\n",
        "def classify_email_ic(email_content):\n",
        "    \"\"\"\n",
        "    Classifies an email as 'Malicious' or 'Benign' using a role-specific prompt with examples.\n",
        "\n",
        "    Args:\n",
        "        email_content (str): The content of the email to be classified.\n",
        "\n",
        "    Returns:\n",
        "        str: 'Malicious' or 'Benign' based on the model's evaluation.\n",
        "    \"\"\"\n",
        "    # Prepare the messages for ChatCompletion\n",
        "    messages = [\n",
        "        {\"role\": \"system\", \"content\": \"You are a cybersecurity expert specialized in identifying malicious emails, such as phishing or spam. Analyze the content of each email and classify it as 'Malicious' or 'Benign' based on suspicious patterns.\"},\n",
        "        {\"role\": \"user\", \"content\": \"\"\"\n",
        "Examples:\n",
        "---\n",
        "Email: \"Dear customer, your bank account has been blocked. Click on the following link to verify your details: http://fake-link.com\"\n",
        "Classification: Malicious\n",
        "---\n",
        "Email: \"Hi John, would you like to go out for dinner tonight? Let me know! - Sarah\"\n",
        "Classification: Benign\n",
        "---\n",
        "Email: \"Congratulations, you won a cash prize. Click here to claim: http://fake-prize.com\"\n",
        "Classification: Malicious\n",
        "---\n",
        "Email: \"Dear user, your subscription to our service will expire soon. Visit our site for more information: https://legit-company.com/update\"\n",
        "Classification: Benign\n",
        "---\n",
        "Email: \"ATTENTION! We detected an issue with your account. Verify immediately by clicking here: http://unsafe-link.com\"\n",
        "Classification: Malicious\n",
        "---\n",
        "\n",
        "Classify the following email:\n",
        "\n",
        "Email:\n",
        "\"\"\" + email_content + \"\\nClassification:\"}\n",
        "    ]\n",
        "\n",
        "    # Create the chat completion with the new client format\n",
        "    response = client.chat.completions.create(\n",
        "        model=\"gpt-3.5-turbo\",\n",
        "        messages=messages,\n",
        "        max_tokens=10,\n",
        "        temperature=0\n",
        "    )\n",
        "\n",
        "    # Accessing the classification result from the response using object attributes\n",
        "    classification = response.choices[0].message.content.strip()  # Changed this line\n",
        "    return classification"
      ],
      "metadata": {
        "id": "YmmmdkR5zLWl"
      },
      "execution_count": null,
      "outputs": []
    },
    {
      "cell_type": "markdown",
      "source": [
        "# 3. Sample email classification"
      ],
      "metadata": {
        "id": "AT-czz0g0OAA"
      }
    },
    {
      "cell_type": "code",
      "source": [
        "# 3. Sample email classification with updated Chat API\n",
        "sample_email = \"\"\"\n",
        "Dear user, your account has been temporarily suspended.\n",
        "To reactivate your account, please click on the following link: http://fake-link.com\n",
        "Best regards, Support Team.\n",
        "\"\"\"\n",
        "\n",
        "# Classify the sample email\n",
        "classification = classify_email_ic(sample_email)\n",
        "print(f\"Sample email classification: {classification}\")\n"
      ],
      "metadata": {
        "colab": {
          "base_uri": "https://localhost:8080/"
        },
        "id": "p_wINZ730M44",
        "outputId": "82aa2a3c-be83-459e-940e-e9ce83e6d397"
      },
      "execution_count": null,
      "outputs": [
        {
          "output_type": "stream",
          "name": "stdout",
          "text": [
            "Sample email classification: Classification: Malicious\n"
          ]
        }
      ]
    },
    {
      "cell_type": "markdown",
      "source": [
        "# 4. Automate classification of emails from the inbox using the Gmail API"
      ],
      "metadata": {
        "id": "8AlmT_VaMoZ1"
      }
    },
    {
      "cell_type": "code",
      "source": [
        "pip install --upgrade google-api-python-client google-auth-httplib2 google-auth-oauthlib"
      ],
      "metadata": {
        "id": "9AUcpQf6vaio",
        "outputId": "7b079e8c-2396-452f-94c6-c204c77d41a3",
        "colab": {
          "base_uri": "https://localhost:8080/"
        }
      },
      "execution_count": null,
      "outputs": [
        {
          "output_type": "stream",
          "name": "stdout",
          "text": [
            "Requirement already satisfied: google-api-python-client in /usr/local/lib/python3.10/dist-packages (2.137.0)\n",
            "Collecting google-api-python-client\n",
            "  Downloading google_api_python_client-2.151.0-py2.py3-none-any.whl.metadata (6.7 kB)\n",
            "Requirement already satisfied: google-auth-httplib2 in /usr/local/lib/python3.10/dist-packages (0.2.0)\n",
            "Requirement already satisfied: google-auth-oauthlib in /usr/local/lib/python3.10/dist-packages (1.2.1)\n",
            "Requirement already satisfied: httplib2<1.dev0,>=0.19.0 in /usr/local/lib/python3.10/dist-packages (from google-api-python-client) (0.22.0)\n",
            "Requirement already satisfied: google-auth!=2.24.0,!=2.25.0,<3.0.0.dev0,>=1.32.0 in /usr/local/lib/python3.10/dist-packages (from google-api-python-client) (2.27.0)\n",
            "Requirement already satisfied: google-api-core!=2.0.*,!=2.1.*,!=2.2.*,!=2.3.0,<3.0.0.dev0,>=1.31.5 in /usr/local/lib/python3.10/dist-packages (from google-api-python-client) (2.19.2)\n",
            "Requirement already satisfied: uritemplate<5,>=3.0.1 in /usr/local/lib/python3.10/dist-packages (from google-api-python-client) (4.1.1)\n",
            "Requirement already satisfied: requests-oauthlib>=0.7.0 in /usr/local/lib/python3.10/dist-packages (from google-auth-oauthlib) (1.3.1)\n",
            "Requirement already satisfied: googleapis-common-protos<2.0.dev0,>=1.56.2 in /usr/local/lib/python3.10/dist-packages (from google-api-core!=2.0.*,!=2.1.*,!=2.2.*,!=2.3.0,<3.0.0.dev0,>=1.31.5->google-api-python-client) (1.65.0)\n",
            "Requirement already satisfied: protobuf!=3.20.0,!=3.20.1,!=4.21.0,!=4.21.1,!=4.21.2,!=4.21.3,!=4.21.4,!=4.21.5,<6.0.0.dev0,>=3.19.5 in /usr/local/lib/python3.10/dist-packages (from google-api-core!=2.0.*,!=2.1.*,!=2.2.*,!=2.3.0,<3.0.0.dev0,>=1.31.5->google-api-python-client) (3.20.3)\n",
            "Requirement already satisfied: proto-plus<2.0.0dev,>=1.22.3 in /usr/local/lib/python3.10/dist-packages (from google-api-core!=2.0.*,!=2.1.*,!=2.2.*,!=2.3.0,<3.0.0.dev0,>=1.31.5->google-api-python-client) (1.25.0)\n",
            "Requirement already satisfied: requests<3.0.0.dev0,>=2.18.0 in /usr/local/lib/python3.10/dist-packages (from google-api-core!=2.0.*,!=2.1.*,!=2.2.*,!=2.3.0,<3.0.0.dev0,>=1.31.5->google-api-python-client) (2.32.3)\n",
            "Requirement already satisfied: cachetools<6.0,>=2.0.0 in /usr/local/lib/python3.10/dist-packages (from google-auth!=2.24.0,!=2.25.0,<3.0.0.dev0,>=1.32.0->google-api-python-client) (5.5.0)\n",
            "Requirement already satisfied: pyasn1-modules>=0.2.1 in /usr/local/lib/python3.10/dist-packages (from google-auth!=2.24.0,!=2.25.0,<3.0.0.dev0,>=1.32.0->google-api-python-client) (0.4.1)\n",
            "Requirement already satisfied: rsa<5,>=3.1.4 in /usr/local/lib/python3.10/dist-packages (from google-auth!=2.24.0,!=2.25.0,<3.0.0.dev0,>=1.32.0->google-api-python-client) (4.9)\n",
            "Requirement already satisfied: pyparsing!=3.0.0,!=3.0.1,!=3.0.2,!=3.0.3,<4,>=2.4.2 in /usr/local/lib/python3.10/dist-packages (from httplib2<1.dev0,>=0.19.0->google-api-python-client) (3.2.0)\n",
            "Requirement already satisfied: oauthlib>=3.0.0 in /usr/local/lib/python3.10/dist-packages (from requests-oauthlib>=0.7.0->google-auth-oauthlib) (3.2.2)\n",
            "Requirement already satisfied: pyasn1<0.7.0,>=0.4.6 in /usr/local/lib/python3.10/dist-packages (from pyasn1-modules>=0.2.1->google-auth!=2.24.0,!=2.25.0,<3.0.0.dev0,>=1.32.0->google-api-python-client) (0.6.1)\n",
            "Requirement already satisfied: charset-normalizer<4,>=2 in /usr/local/lib/python3.10/dist-packages (from requests<3.0.0.dev0,>=2.18.0->google-api-core!=2.0.*,!=2.1.*,!=2.2.*,!=2.3.0,<3.0.0.dev0,>=1.31.5->google-api-python-client) (3.4.0)\n",
            "Requirement already satisfied: idna<4,>=2.5 in /usr/local/lib/python3.10/dist-packages (from requests<3.0.0.dev0,>=2.18.0->google-api-core!=2.0.*,!=2.1.*,!=2.2.*,!=2.3.0,<3.0.0.dev0,>=1.31.5->google-api-python-client) (3.10)\n",
            "Requirement already satisfied: urllib3<3,>=1.21.1 in /usr/local/lib/python3.10/dist-packages (from requests<3.0.0.dev0,>=2.18.0->google-api-core!=2.0.*,!=2.1.*,!=2.2.*,!=2.3.0,<3.0.0.dev0,>=1.31.5->google-api-python-client) (2.2.3)\n",
            "Requirement already satisfied: certifi>=2017.4.17 in /usr/local/lib/python3.10/dist-packages (from requests<3.0.0.dev0,>=2.18.0->google-api-core!=2.0.*,!=2.1.*,!=2.2.*,!=2.3.0,<3.0.0.dev0,>=1.31.5->google-api-python-client) (2024.8.30)\n",
            "Downloading google_api_python_client-2.151.0-py2.py3-none-any.whl (12.5 MB)\n",
            "\u001b[2K   \u001b[90m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\u001b[0m \u001b[32m12.5/12.5 MB\u001b[0m \u001b[31m84.6 MB/s\u001b[0m eta \u001b[36m0:00:00\u001b[0m\n",
            "\u001b[?25hInstalling collected packages: google-api-python-client\n",
            "  Attempting uninstall: google-api-python-client\n",
            "    Found existing installation: google-api-python-client 2.137.0\n",
            "    Uninstalling google-api-python-client-2.137.0:\n",
            "      Successfully uninstalled google-api-python-client-2.137.0\n",
            "Successfully installed google-api-python-client-2.151.0\n"
          ]
        }
      ]
    },
    {
      "cell_type": "code",
      "source": [
        "import os.path\n",
        "from google.auth.transport.requests import Request\n",
        "from google.oauth2.credentials import Credentials\n",
        "from google_auth_oauthlib.flow import InstalledAppFlow\n",
        "from googleapiclient.discovery import build\n",
        "from googleapiclient.errors import HttpError\n",
        "\n",
        "# Define the scope for read-only access to Gmail\n",
        "SCOPES = [\"https://www.googleapis.com/auth/gmail.readonly\"]\n",
        "\n",
        "def main():\n",
        "    \"\"\"Reads emails with the label 'purchases/orders' and classifies them.\"\"\"\n",
        "    creds = None\n",
        "    # Load credentials or authenticate if necessary\n",
        "    if os.path.exists(\"{{TOKEN.json}}\"):\n",
        "        creds = Credentials.from_authorized_user_file(\"{{TOKEN.json}}\", SCOPES)\n",
        "    if not creds or not creds.valid:\n",
        "        if creds and creds.expired and creds.refresh_token:\n",
        "            creds.refresh(Request())\n",
        "        else:\n",
        "            flow = InstalledAppFlow.from_client_secrets_file(\n",
        "                \"{{your_credentials.json}}\", SCOPES\n",
        "            )\n",
        "            creds = flow.run_local_server(port=0)\n",
        "        # Save the credentials for future use\n",
        "        with open(\"{{TOKEN.json}}\", \"w\") as token:\n",
        "            token.write(creds.to_json())\n",
        "\n",
        "    try:\n",
        "        # Build the Gmail API service\n",
        "        service = build(\"gmail\", \"v1\", credentials=creds)\n",
        "\n",
        "        # Search for emails with the label 'purchases/orders'\n",
        "        results = service.users().messages().list(userId=\"me\", labelIds=[\"Label_2632497382483817671\"]).execute()\n",
        "        messages = results.get(\"messages\", [])\n",
        "\n",
        "        if not messages:\n",
        "            print(\"No emails found with the label 'purchases/orders'.\")\n",
        "            return\n",
        "\n",
        "        print(\"Emails with label 'purchases/orders':\")\n",
        "        for message in messages:\n",
        "            msg = service.users().messages().get(userId=\"me\", id=message[\"id\"]).execute()\n",
        "            email_content = msg.get(\"snippet\", \"No snippet available\")\n",
        "\n",
        "            # Classify the email content using classify_email_ic function\n",
        "            classification = classify_email_ic(email_content)\n",
        "            print(f\"Email ID: {message['id']}\\nContent:\\n{email_content}\\nClassification: {classification}\\n\")\n",
        "\n",
        "    except HttpError as error:\n",
        "        print(f\"An error occurred: {error}\")\n",
        "\n",
        "if __name__ == \"__main__\":\n",
        "    main()\n"
      ],
      "metadata": {
        "id": "o-MsWZHkMpcm",
        "colab": {
          "base_uri": "https://localhost:8080/"
        },
        "outputId": "fdf5489f-775a-48bc-c7b7-dcc286aff5ca"
      },
      "execution_count": null,
      "outputs": [
        {
          "output_type": "stream",
          "name": "stdout",
          "text": [
            "Emails with label 'purchases/orders':\n",
            "Email ID: 18e4e15aea35fefa\n",
            "Content:\n",
            "ESTIMADO CLIENTE ADJUTNO ENCONTRARA DETALLE DE LA FACTURA A ABONAR POR FAVOR ENVIE COMPROBANTE DEL APGO INDICANDO NUMERO DE FACTURA CUALQUIER CONSULTA , A DISPOSICION MYPREPCENTERLLC@GMAIL.COM\n",
            "Classification: Classification: Malicious\n",
            "\n",
            "This email exhibits suspicious characteristics\n",
            "\n",
            "Email ID: 18e4a1cd7a597589\n",
            "Content:\n",
            "ESTIMADO CLIENTE ADJUTNO ENCONTRARA DETALLE DE LA FACTURA A ABONAR POR FAVOR ENVIE COMPROBANTE DEL APGO INDICANDO NUMERO DE FACTURA CUALQUIER CONSULTA , A DISPOSICION MYPREPCENTERLLC@GMAIL.COM\n",
            "Classification: Classification: Malicious\n",
            "\n",
            "This email exhibits suspicious characteristics\n",
            "\n",
            "Email ID: 18e021d4fa9e5c37\n",
            "Content:\n",
            "ESTIMADO CLIENTE ADJUTNO ENCONTRARA DETALLE DE LA FACTURA A ABONAR POR FAVOR ENVIE COMPROBANTE DEL APGO INDICANDO NUMERO DE FACTURA CUALQUIER CONSULTA , A DISPOSICION MYPREPCENTERLLC@GMAIL.COM\n",
            "Classification: Classification: Malicious\n",
            "\n",
            "This email exhibits suspicious characteristics\n",
            "\n",
            "Email ID: 18deb2866543b432\n",
            "Content:\n",
            "Buen día! adjunto el comprobante de pago transactionId: 646768456 El lun, 26 feb 2024 a la(s) 9:22 pm, &lt;myprepcenterllc@app.invoicehome.com&gt; escribió: ESTIMADO CLIENTE ADJUTNO ENCONTRARA DETALLE\n",
            "Classification: Classification: Benign\n",
            "\n",
            "Email ID: 18de7f11c3f877a6\n",
            "Content:\n",
            "ESTIMADO CLIENTE ADJUTNO ENCONTRARA DETALLE DE LA FACTURA A ABONAR POR FAVOR ENVIE COMPROBANTE DEL APGO INDICANDO NUMERO DE FACTURA CUALQUIER CONSULTA , A DISPOSICION MYPREPCENTERLLC@GMAIL.COM\n",
            "Classification: Classification: Malicious\n",
            "\n",
            "This email exhibits suspicious characteristics\n",
            "\n"
          ]
        }
      ]
    },
    {
      "cell_type": "code",
      "source": [],
      "metadata": {
        "id": "cyvcVDFxe6yl"
      },
      "execution_count": null,
      "outputs": []
    }
  ]
}
