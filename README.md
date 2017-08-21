# Item Catalog

**Create and store a simple online catalog of items**

This application hosts a digital item catalog.

Allows users to browse the catalog of items
and show items in each category.

Allows logged in users to add items to a catalog,
assign a photo and category to each item as well as update/edit/delete
items they previously added.

Because the app runs on the Flask web framework and uses SQL Alchemy
it can be easily configured to run in many server and database environments.

The app authorization and authentication is provided using **OAUTH2**
and is set up to use secure **Google and Microsoft OAUTH2 login**.

In order to create, update, or delete items from the catalog,
users can login using either Google or Microsoft/Azure AD accounts.

## Setup

To set the app up for initial use, you need to do 3 things:

1. Configure an SQLAlchemy compatible database to connect to the application.
2. Complete application registration through Google and Microsoft (for OAUTH2).
3. Install Python and dependencies.

To get the app up and running you will need to save two configuration files
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

___

#### Application Registration through Google and Microsoft

Because the app uses OAUTH2 to provide authentication
it has to be registered with the OAUTH2 providers through their
developer portals.

This involves creating a Google Account and Microsoft Account
then registing your application.

##### Registering with Google
First, you need a google account.

Then, Follow the steps here:
https://support.google.com/cloud/answer/6158849?hl=en

For the Consent Screen you need an email address and a Product name which will be shown to users.

For Authorized Javascript origins use the main URL of the app

`https://www.sitename.com`

For authorized redirect URIs use
`https://www.sitename.com/login/`
`https://www.sitename.com/gconnect/`


Once you are done setting up the OAuth2 Credentials
you have the option to `download JSON` with the download button.

Download the file, and save it as `client_secrets.json`
in the application main directory (or use a symlink to it).

##### Registering with Microsoft
First, you need a Microsoft Account

Then follow the steps here:
https://developer.microsoft.com/en-us/graph/docs/concepts/auth_register_app_v2

Follow the steps for web apps, and make
sure Allow Implicit Flow is enabled.

The redirect URLs used by the app by default are
the URL of the app

`https://www.sitename.com`
and
`https://www.sitename.com/msconnect/`

You need to put these URLs in `config.ini` (continue reading)

The logout URL by default is
`https://www.sitename.com/logout/`

For Microsoft Graph Permissions: the only one needed
for this app is `User.Read`

The other information such as Terms of Service and
Privacy Statement, Logo etc are optional but are
recommended by Microsoft.

Also under advanced options, enable Live SDK support.

There are 2 pieces of info you need from this portal
for the `config.ini` file so login will work properly.
Application ID and Application Secret

The Application ID is available after the app is registered
and is in the form of a GUID.

The Application Secret is randomly
generated and is only available when
you create it so be sure to copy and
paste it into the `config.ini` file.

There should be 2 entries in `config.ini` pertaining to Microsoft in the `[app-keys]` section like so:


    [app-keys]
    MicrosoftID: 0cb...30b4
    MicrosoftSecretKey: v51....G6


and two entries under `[ms-oauth2]`, the redirect URLs from earlier.

    [ms-oauth2]
    main-url: https://www.sitename.com
    msconnect-url: https://www.sitename.com/msconnect/

___

#### Install Python and dependencies

First you need Python 2 installed.

Follow the guide here for your Operating System.

http://docs.python-guide.org/en/latest/starting/installation/

Once that is done, you need to install Flask and the other Python code dependencies. The easiest way is using PIP.

`pip install -r requirements.txt`
___

### Preparing config files

Once you have completed these steps- go to the `config.ini`
file and ensure a Secret Key is set here. Make sure the secret
key is cryptographically strong, as it is the
basis for anti-tamper security the app uses.

A complete `config.ini` file should look something like this:


    [database]
    url: postgresql:///items.db

    [app-keys]
    # Secret Keys and App ids used for app and external APIS
    AppSecretKey: fake-placeholder-key

    MicrosoftID: 0cb...30b4
    MicrosoftSecretKey: v51....G6

    [ms-oauth2]
    main-url: https://www.sitename.com
    msconnect-url: https://www.sitename.com/msconnect/

and as a reminder, you should have the `client_secrets.json` file
that was exported from Google after registering the app.

Both `config.ini` and `client_secrets.json` belong
in the main app directory (with main.py).



## Running App
Once that is done, you start the catalog by running
main.py

`python main.py`

If everything is working properly you should see

`
Running on http://0.0.0.0:5000/ (Press CTRL+C to quit)
`

This means the app is up and running and serving requests. You should be able to visit the URL to see the catalog in action.

You can test the third party Logins using the accounts you made earlier and if they work then OAUTH2 is working properly.

You can change the port used by the app
by modifying the `port=5000` keyword at the bottom of the file.

### Issues and Suggestions

If you run into any issues running the app or have any ideas for improvement feel free to open an issue on github.


# Built with Help From

### Python 2

https://www.python.org/

https://docs.python.org/2/license.html

### Flask
https://github.com/pallets/flask/

https://github.com/pallets/flask/blob/master/LICENSE

### Python Imaging Library (PIL)

http://pythonware.com/products/pil/

http://www.pythonware.com/products/pil/license.htm

### SQLAlchemy

http://www.sqlalchemy.org/

https://github.com/zzzeek/sqlalchemy/blob/master/LICENSE

### Microsoft Corp
Application uses Microsoft APIs to sign users in.
This project is otherwise not affiliated with Microsoft Corp.

Logo used with implied permission from

https://docs.microsoft.com/en-us/azure/active-directory/develop/active-directory-branding-guidelines#user-account-pictogram


### Google
Application uses Google APIs to sign users in.
This project is otherwise not affiliated with Google.

Logo is loaded from Google Servers and not included as an application asset.
