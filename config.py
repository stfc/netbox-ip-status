import os
from dotenv import load_dotenv
load_dotenv()

API_KEY = os.getenv("NETBOX_API_KEY")
NETBOX_URL = os.getenv("NETBOX_URL")
PREFIX_TAG = os.getenv("NETBOX_PREFIX_TAG")
