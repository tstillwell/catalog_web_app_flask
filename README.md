# Item Catalog

**Create and store a simple online catalog of items**

This application hosts a digital item catalog.

Out of box, it supports uploading a single image per item and assigning
a single category to each item.

Because the app runs on the popular Flask web framework and uses SQL Alchemy
it can be easily configured to run in many server and database environments.

The app authorization and authentication is provided using OAUTH2
and is set up to use secure Google and Microsoft OAUTH2 login.

In order to create, update, or delete items from the catalog,
catalog administrators can use either Google or Microsoft/Azure AD accounts.

## Setup

To set the app up, you need to do 3 things:

1. Configure an SQLAlchemy compatible database to connect to the application.
2. Complete application registration through Google and Microsoft (for OAUTH2).
3. Install Flask and Python dependencies.

To get the app up and running you will need two configuration files
`config.ini` and `client_secrets.json`

#### Database

##### Choosing a database

As mentioned, the app uses SQLAlchemy toolkit.
SQLAlchemy is an ORM for Python that works with
multiple different RDBMS installations.

http://docs.sqlalchemy.org/en/latest/dialects/

You can either use an existing RDBMS you have pre-installed on your system
or install one for the app.

If you do not have one installed and don't have a preference- it is recommended
to use PostgreSQL, as it is Free and Open Source and well documented.

Note: You only need to have the RDBMS installed,
the code creates/connects to the database automatically.

Follow the corresponding installation documentation for your database
and verify your database is working properly.

##### Getting the database URL

Once your database is set up
you need to get the **database URL**
for the configuration.

Typically this is a URL that specifies the database type first
then the hostname/database name. The database URL will vary depending
on if you are connecting to a local database or a remote database
and other info such as port number and security setup.

Once you have the URL it should go in the `config.ini`
file under the `[database]` section like this:

    
    [database]
    url: postgresql://items.db
    

Normally, If a database exists at that location the app will use it
if one does not exist it will be created.

#### Application Registartion through Google and Microsoft

Because the app uses OAUTH2 to provide authentication
it has to be registered with the OAUTH2 providers through their
developer portals.

This involves creating a Google Account and Microsoft Account
then registing your application.

##### Registering with Google
First, you need a google account.

Then, Follow the steps here:
https://support.google.com/cloud/answer/6158849?hl=en

Once you are done setting up the OAuth2 Credentials
you have the option to `download JSON` with the download button.

Download the file, and save it as `client_secrets.json`
in the application main directory.




