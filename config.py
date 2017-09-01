"""
Reads config from config.ini and client_secrets.json

Configures database session object used by SQLAlchemy
to read & update database.
Reads client ids/client secrets & database url from
config files.
All relevant info is imported by main.py 'import config'
More info available in README file.
"""

import ConfigParser
import json
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from database_setup import Base

config = ConfigParser.RawConfigParser()

try:
    config.read('config.ini')
except IOError:
    print "config.ini cannot be opened"
    raise

try:  # Read database URL from config.ini file
    DB_URL = config.get('database', 'url')
except ConfigParser.NoOptionError:
    print("Could not read database URL value from config.ini")
except ConfigParser.NoSectionError:
    print("[database] section is not present in config.ini")

# Database configuration/ORM variables used for accessing external db
engine = create_engine(DB_URL)
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)
session = DBSession()

try:
    APP_SECRET = config.get('app-keys', 'AppSecretKey')
    MS_APP_ID = config.get('app-keys', 'MicrosoftID')
    MS_SECRET = config.get('app-keys', 'MicrosoftSecretKey')
except ConfigParser.NoOptionError:
    print("Could not read all app-key values from config.ini")
except ConfigParser.NoSectionError:
    print("[app-keys] section is not present in config.ini")

try:
    MS_MAIN_URL = config.get('ms-oauth2', 'main-url')
    MS_CONNECT_URL = config.get('ms-oauth2', 'msconnect-url')
except ConfigParser.NoOptionError:
    print("Could not read url values from config.ini")
except ConfigParser.NoSectionError:
    print("[ms-oauth2] section is not present in config.ini")

GOOGLE_APP_ID = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']
