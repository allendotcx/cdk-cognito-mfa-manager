from aws_cdk import (
    Duration,
    Stack,
    RemovalPolicy,
    aws_lambda as _lambda,
    aws_iam as _iam,
    aws_cognito as cognito,
    aws_apigateway as apigateway,
)

from constructs import Construct

class CognitoMfaManagerStack(Stack):

    def RandomPassword(self):
        chars = string.ascii_uppercase + string.ascii_lowercase + string.digits + string.punctuation
        size = random.randint(16, 20)
        return 'T3m9' + ''.join(random.choice(chars) for x in range(size))


    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        user_pool = cognito.UserPool(self, 'cdk-userpool',
            user_pool_name = 'cognito-demo-01',
            removal_policy = RemovalPolicy.DESTROY,
            self_sign_up_enabled = False,
            sign_in_aliases = { 'email': True },
            auto_verify = {'email': True},
            password_policy = {
                'min_length': 8,
                'require_lowercase': True,
                'require_digits': True,
                'require_uppercase': True,
                'require_symbols': True,
                },
            account_recovery = cognito.AccountRecovery.EMAIL_ONLY,
            mfa = cognito.Mfa.OPTIONAL,
            mfa_second_factor = {
                'otp': True,
                'sms': False
                },
            )

        user_pool_client = user_pool.add_client("userpool-mfa-manager-client",
            generate_secret = True,
            auth_flows=cognito.AuthFlow(
                user_password=True,
                user_srp=True,
                admin_user_password=True,
                custom=False,
                ),
            supported_identity_providers = [
                cognito.UserPoolClientIdentityProvider.COGNITO,
                ],
            )

        user_pool_client.apply_removal_policy(RemovalPolicy.DESTROY)

        lambda_role = _iam.Role(scope=self, id='cdk-lambda-role',
            assumed_by =_iam.ServicePrincipal('lambda.amazonaws.com'),
            role_name='lambda-role',
            managed_policies=[
                _iam.ManagedPolicy.from_aws_managed_policy_name(
                'service-role/AWSLambdaVPCAccessExecutionRole'),
                _iam.ManagedPolicy.from_aws_managed_policy_name(
                'service-role/AWSLambdaBasicExecutionRole'),
            ])

        lambda_role.add_to_policy(_iam.PolicyStatement(
            effect=_iam.Effect.ALLOW,
            resources=[ "*" ],
            actions=[
                "cognito-idp:ListUsers",
                "Cognito-idp:AdminCreateUser",
                "Cognito-idp:AdminDeleteUser",
                "cognito-idp:AdminSetUserMFAPreference",
                "cognito-idp:AdminSetUserPassword",
                "cognito-idp:AdminGetUser",
                "cognito-idp:AdminEnableUser",
                "cognito-idp:AdminDisableUser",
                "cognito-idp:AdminConfirmSignUp",
                "cognito-idp:AdminResetUserPassword",
                "cognito-idp:AdminInitiateAuth",
                "cognito-idp:AdminRespondToAuthChallenge",
                "cognito-idp:AdminResetUserSettings",
            ])
        )

        manager_lambda = _lambda.Function(
            self, 'cognito-mfa-manager',
            runtime=_lambda.Runtime.PYTHON_3_7,
            function_name='cognito-mfa-manager',
            code=_lambda.Code.from_asset('./lambda/cognitomanager'),
            handler='lambda-handler.handler',
            role=lambda_role,
            environment={
                "cognito_client_id": user_pool_client.user_pool_client_id,
                "cognito_client_secret": "",
                "cognito_user_pool_id": user_pool.user_pool_id
                },
            )

        #
        # Lambda - Cognito API Gateway
        # create api
        # create Authorizer
        # set the authorizer on the route.
        #

        manager_api = apigateway.RestApi(self, "cognito-mfa-manager-api",
            rest_api_name = "Cognito MFA Manager API",
            description = "Cognito MFA Manager API.",
            deploy_options = {
                'stage_name': 'dev',
            },
            #      // 👇 enable CORS
            default_cors_preflight_options = {
                'allow_headers': [
                    'Content-Type',
                    'X-Amz-Date',
                    'Authorization',
                    'X-Api-Key',
                ],
                #'allow_methods': ['OPTIONS', 'GET', 'POST', 'PUT', 'PATCH', 'DELETE'],
                'allow_methods': ['POST'],
                'allow_credentials': True,
                "allow_origins": ["*"],
                }
            )

        manager_integration = apigateway.LambdaIntegration(manager_lambda,
            passthrough_behavior = apigateway.PassthroughBehavior.NEVER,
            proxy = False,
            request_templates = { "application/json": "$input.body" },
            integration_responses = [
                apigateway.IntegrationResponse(
                    status_code = "200",
                    response_parameters = {
                        "method.response.header.Access-Control-Allow-Origin": "'*'",
                        'method.response.header.Content-Type': "'application/json'",
                })]
            )

        # authorizer
        # cognito_auth = apigateway.CfnAuthorizer(
        #     self, "mfaManagerAuthorizer",
        #     name = "mfaManagerAuthorizer",
        #     rest_api_id = manager_api.rest_api_id,
        #     type = 'COGNITO_USER_POOLS',
        #     identity_source='method.request.header.Authorization',
        #     provider_arns =  [ user_pool.user_pool_arn ],
        # )

        manager_resource = manager_api.root.add_resource('cognitomanager')
        post_method = manager_resource.add_method(
            "POST",
            manager_integration,
            method_responses = [
                apigateway.MethodResponse(
                    status_code = "200",
                    response_parameters = {
                        'method.response.header.Access-Control-Allow-Headers': True,
                        'method.response.header.Access-Control-Allow-Origin': True,
                        'method.response.header.Content-Type': True
                    },
                )],
        )

        # method_resource = post_method.node.find_child('Resource')
        # method_resource.add_property_override('AuthorizationType', 'COGNITO_USER_POOLS')
        # method_resource.add_property_override( 'AuthorizerId', {"Ref": cognito_auth.logical_id})
