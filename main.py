try:
    import json
    import time
    from random import randint
    import datetime
    from requests.auth import HTTPBasicAuth
    import requests
    import threading
    import stripe
    from telegram import Update
    from telegram.ext import Application, CommandHandler, ContextTypes
    import asyncio
    import re
    from concurrent.futures import ThreadPoolExecutor
    import urllib3
    import warnings
    from faker import Faker
    from user_agents import parse
    import random
except Exception as e:
    print("Libraries not installed! Please install them with pip")
