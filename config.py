from dotenv import load_dotenv
import os
from datetime import timedelta
load_dotenv()
BLOCKLIST_EXPIRE_DAYS = timedelta(days=30)
MONGODB_URL = os.getenv("MONGODB_URL")