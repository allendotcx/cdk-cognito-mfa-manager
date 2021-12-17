# AWS Cognito MFA
# MFA is not configured by default when using the AWS Cognito web UI.
# The following script will setup a user account, setup MFA for the user, and return a temporary password.

import boto3, json
import string, random
import os
import hmac, hashlib, base64
from lib import pyotp

class CognitoMFA:
    def __init__(self, USERNAME, EMAIL, TEMP_PASSWORD, CLIENT_ID, CLIENT_SECRET, USER_POOL_ID):
        self.USERNAME = USERNAME
        self.TEMP_PASSWORD = TEMP_PASSWORD
        self.CLIENT_ID = CLIENT_ID
        self.CLIENT_SECRET = CLIENT_SECRET
        self.USER_POOL_ID = USER_POOL_ID
        self.EMAIL = EMAIL
        self.SECRET_HASH = ''
        self.ACCESS_TOKEN = ''
        self.SECRET_TOKEN = ''
        # Create boto3 client for cognito to use
        self.client = boto3.client('cognito-idp')

    def __str__(self):
        return self.SECRET_HASH

    # Get the mysterious secret hash
    def GetSecretHash(self):
        message = bytes(self.USERNAME+self.CLIENT_ID,'utf-8')
        key = bytes(self.CLIENT_SECRET,'utf-8')
        self.SECRET_HASH = base64.b64encode(hmac.new(key, message, digestmod=hashlib.sha256).digest()).decode()
        return self.SECRET_HASH

    # Get a password that meets compliance
    def RandomPassword(self):
        chars = string.ascii_uppercase + string.ascii_lowercase + string.digits + string.punctuation
        size = random.randint(16, 20)
        return 'T3m9' + ''.join(random.choice(chars) for x in range(size))

    # Create the user account
    def CreateUser(self):
        response = self.client.admin_create_user(
            UserPoolId = self.USER_POOL_ID,
            Username = self.USERNAME,
            UserAttributes=[
                {
                    'Name': 'email',
                    'Value': self.EMAIL
                },
                {
                    'Name': 'email_verified',
                    'Value': 'true'
                }
            ],
            TemporaryPassword = self.TEMP_PASSWORD,
            MessageAction = 'SUPPRESS',
            DesiredDeliveryMediums = [
                'EMAIL',
            ]
        )

    # Change the users password for enabling mfa
    def SetUserPassword(self, permState, random):
        if (random == 'y'):
            password = self.RandomPassword()
        else:
            password = self.TEMP_PASSWORD
        response = self.client.admin_set_user_password(
            UserPoolId = self.USER_POOL_ID,
            Username = self.USERNAME,
            Password = password,
            Permanent = permState
        )
        return password

    # Get the user token
    def GetUserToken(self):
        initiateAuth = self.client.initiate_auth(
            AuthFlow = "USER_PASSWORD_AUTH",
            AuthParameters = {
                'USERNAME': self.USERNAME,
                'PASSWORD': self.TEMP_PASSWORD,
                'SECRET_HASH': self.SECRET_HASH
            },
            ClientId = self.CLIENT_ID
        )
        self.ACCESS_TOKEN = initiateAuth["AuthenticationResult"]["AccessToken"]
        return self.ACCESS_TOKEN

    # Get the mfa token
    def GetMFAToken(self):
        associateSoftwareToken = self.client.associate_software_token(
            AccessToken = self.ACCESS_TOKEN
        )
        self.SECRET_TOKEN = associateSoftwareToken["SecretCode"]
        return self.SECRET_TOKEN

    # Verify the token
    def VerifyToken(self):
        totp = pyotp.TOTP(self.SECRET_TOKEN)
        response = self.client.verify_software_token(
            AccessToken = self.ACCESS_TOKEN,
            UserCode = totp.now()
        )

    # Enable on mfa for the user account
    def EnableUserMFA(self):
        response = self.client.admin_set_user_mfa_preference(
            SoftwareTokenMfaSettings = {
                'Enabled': True,
                'PreferredMfa': True
            },
            Username = self.USERNAME,
            UserPoolId = self.USER_POOL_ID
        )

    def EnableCognitoUser(self):
        response = self.client.admin_enable_user(
            Username = self.USERNAME,
            UserPoolId = self.USER_POOL_ID
        )
        return response

    def DisableCognitoUser(self):
        response = self.client.admin_disable_user(
            UserPoolId=self.USER_POOL_ID,
            Username=self.USERNAME
        )
        return response

    def DisableUserMFA(self):
        response = self.client.admin_set_user_mfa_preference(
            SoftwareTokenMfaSettings={
                'Enabled': False,
                'PreferredMfa': False
            },
            Username=self.USERNAME,
            UserPoolId=self.USER_POOL_ID
        )
        return response

    def DeleteUser(self):
        response = self.client.admin_delete_user(
            UserPoolId=self.USER_POOL_ID,
            Username=self.USERNAME
        )
        return response

    def get_all_users(self):
        cognito = self.client
        users = []
        next_page = None
        kwargs = {
            'UserPoolId': self.USER_POOL_ID
        }
        users_remain = True
        while(users_remain):
            if next_page:
                kwargs['PaginationToken'] = next_page
            response = cognito.list_users(**kwargs)

            r_users = response['Users']
            for user in r_users:
                user_create_date = '{:%d/%m/%y %H:%M %S}'.format(user['UserCreateDate'])
                user_last_modified = '{:%d/%m/%y %H:%M %S}'.format(user['UserLastModifiedDate'])
                #mfa_status = user['MFAOptions']

                if( 'MFAOptions' in user.keys()):
                    mfa_options = user['MFAOptions']
                else:
                    mfa_options = []


                email = {}
                attributes = user['Attributes']
                for item in attributes:
                     if(item['Name'] == 'email' or item['Name'] == 'email_verified'):
                         email[item['Name']] = item['Value']

                users.append({
                    'Username': user['Username'],
                    'Email': email['email'],
                    'EmailVerified': email['email_verified'],
                    'Enabled': user['Enabled'],
                    'UserCreateDate': user_create_date,
                    'UserLastModifiedDate': user_last_modified,
                    'UserStatus': user['UserStatus'],
                    #'MFAOptions': list(user['MFAOptions']),
                    'fields': list(user.keys()),
                })
            next_page = response.get('PaginationToken', None)
            users_remain = next_page is not None


        return users


# standardised exception handling
def throw_exception(status_code, message, e):
    return status_code, { 'message': 'Failed: '+ message, 'reason': getattr(e, 'message' , str(e)) }


## Lambda Actions
def action_createUser(R):
    description = 'Create User'
    try:
        R.GetSecretHash()
        R.CreateUser()
        R.SetUserPassword(True, 'n')
        R.GetUserToken()
        MFA_TOKEN = R.GetMFAToken()
        R.VerifyToken()
        R.EnableUserMFA()
        Password = R.SetUserPassword(False, 'y')

        return 200, { 'message': description, 'mfa_token': MFA_TOKEN, 'password': Password }
    except Exception as e:
        return throw_exception(500, description, e)

def action_resetUserMfaPassword(R):
    description = 'Reset Password and MFA'
    try:
        R.DisableUserMFA()
        R.GetSecretHash()
        R.SetUserPassword(True, 'n')
        R.GetUserToken()
        MFA_TOKEN = R.GetMFAToken()
        R.VerifyToken()
        R.EnableUserMFA()
        Password = R.SetUserPassword(False, 'y')
        return 200, { 'message':description, 'mfa_token': MFA_TOKEN, 'password': Password }
    except Exception as e:
        return throw_exception(500, description, e)

def action_resetPassword(R):
    description = 'Reset Password Only'
    try:
        Password = R.SetUserPassword(False, 'y')
        return 200, { 'message': description, 'password': Password }
    except Exception as e:
        return throw_exception(500, description, e)

def action_enableUser(R):
    description = 'Enable User (reset password and MFA)'
    try:
        R.EnableCognitoUser()
        (status_code, result) = action_resetUserMfaPassword(R)
        if( status_code == 200 ):
            result['message'] = description
            return 200, result
        else:
            return status_code, result
    except Exception as e:
        return throw_exception(500, description, e)

def action_disableUser(R):
    description = 'Disable User'
    try:
        R.DisableCognitoUser()
        return 200, { 'message': description }
    except Exception as e:
        return throw_exception(500, description, e)

def action_get_all_users(R):
    description = 'Retrieve all users in pool'
    try:
        users = R.get_all_users()
        return 200, { 'message': description, 'users': users }
    except Exception as e:
        return throw_exception(500, description, e)

def action_deleteUser(R):
    description = 'Delete User'
    try:
        R.DeleteUser()
        return 200, { 'message': description }
    except Exception as e:
        return throw_exception(500, description, e)


## Lambda Handler

def handler(event, context):
    # Get arguments from the event
    action = event['action']
    USERNAME = ""
    MFA_TOKEN = ""
    MFA_TOTP =  ""
    EMAIL = ""
    TEMP_PASSWORD = "TempPass123!"

    if( 'username' in event.keys() and event['username'] != ""):
        USERNAME = event['username']
    if( 'email' in event.keys() and event['email'] != ""):
        EMAIL = event['email']

    if( 'mfa_token' in event.keys() and event['mfa_token'] != ""):
        MFA_TOKEN = event['mfa_token']
    if( 'mfa_totp' in event.keys() and event['mfa_totp'] != ""):
        MFA_TOTP = event['mfa_totp']

    # Get arguments from environment
    CLIENT_ID = os.environ['cognito_client_id']
    CLIENT_SECRET = os.environ['cognito_client_secret']
    USER_POOL_ID = os.environ['cognito_user_pool_id']

    R = CognitoMFA(USERNAME, EMAIL, TEMP_PASSWORD, CLIENT_ID, CLIENT_SECRET, USER_POOL_ID)

    status_code = 500
    data = '{ "message": "Internal Server Error: Unknown Error" }'

    if (action == 'get_all_users'):
        (status_code, data) = action_get_all_users(R)

    elif (action == 'create_user'):
        (status_code, data) = action_createUser(R)

    elif (action == 'reset_mfa_token'):
        (status_code, data) = action_resetUserMfaPassword(R)

    elif (action == 'reset_password'):
        (status_code, data) = action_resetPassword(R)

    elif (action == 'enable_user'):
        (status_code, data) = action_enableUser(R)

    elif (action == 'disable_user'):
        (status_code, data) = action_disableUser(R)

    elif (action == 'delete_user'):
        (status_code, data) = action_deleteUser(R)

    else:
        status_code = 400
        data = { 'message': 'Bad Request - Unrecognised action: ' + action }
    # disable MFA
    # enable USER
    # disable USER
    # reset PASSWORD

    data['action'] = action
    if( status_code == 200 ):
        status_result = 'Success'
    else:
        status_result = 'Failed'

    data['result'] = status_result

    return { 'status': status_code, 'body': json.dumps(data) }
