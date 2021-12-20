from aws_cdk import (
    Duration,
    Stack,
    RemovalPolicy,
    aws_lambda as _lambda,
    aws_iam as _iam,
    aws_cognito as cognito,
    aws_apigateway as apigateway,
    aws_s3 as s3,
    aws_s3_deployment as s3deployment,
    aws_cloudfront as cloudfront,
)

from constructs import Construct

class CognitoMfaManagerStack(Stack):

#####################
# Cognito UserPool
    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        CDK_APP_REMOVAL_POLICY = RemovalPolicy.DESTROY

        user_pool = cognito.UserPool(self, 'cdk-userpool',
            user_pool_name = 'cognito-demo-01',
            removal_policy = CDK_APP_REMOVAL_POLICY,
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

        user_pool.add_domain("CognitoDomain",
            cognito_domain=cognito.CognitoDomainOptions(
                domain_prefix="acx21mfamanager"
            )
        )

###############################
## Cognito Client: MFA Manager Lambda

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

        user_pool_client.apply_removal_policy(CDK_APP_REMOVAL_POLICY)

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
            code=_lambda.Code.from_asset('./assets/lambda/cognitomanager'),
            handler='lambda-handler.handler',
            role=lambda_role,
            environment={
                "cognito_client_id": user_pool_client.user_pool_client_id,
                "cognito_client_secret": "",
                "cognito_user_pool_id": user_pool.user_pool_id
                },
            )

        # Cognito Manager API Gateway
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
                }),
                apigateway.IntegrationResponse(
                    status_code = "204",
                    response_parameters = {
                        "method.response.header.Access-Control-Allow-Origin": "'*'",
                        'method.response.header.Content-Type': "'application/json'",
                }),
                ]
            )

        # authorizer
        cognito_auth = apigateway.CfnAuthorizer(
            self, "mfaManagerAuthorizer",
            name = "mfaManagerAuthorizer",
            rest_api_id = manager_api.rest_api_id,
            type = 'COGNITO_USER_POOLS',
            identity_source='method.request.header.Authorization',
            provider_arns =  [ user_pool.user_pool_arn ],
        )

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
                        'method.response.header.Content-Type': True,
                        'method.response.header.Access-Control-Allow-Credentials' : True,
                    },
                ),
                apigateway.MethodResponse(
                    status_code = "204",
                    response_parameters = {
                        'method.response.header.Access-Control-Allow-Headers': True,
                        'method.response.header.Access-Control-Allow-Origin': True,
                        'method.response.header.Content-Type': True,
                        'method.response.header.Access-Control-Allow-Credentials' : True,
                    },
                ),
                ],
        )

        # method_resource = post_method.node.find_child('Resource')
        # method_resource.add_property_override('AuthorizationType', 'COGNITO_USER_POOLS')
        # method_resource.add_property_override( 'AuthorizerId', {"Ref": cognito_auth.logical_id})


####################
## Frontend Web UI
## S3 Bucket Static Website

        # Define S3 Bucket and properties
        s3bucket = s3.Bucket(self, "cognito-manager-webui-bucket",
            removal_policy = CDK_APP_REMOVAL_POLICY,
            website_index_document = "index.html",
            versioned = False,
            auto_delete_objects = True,
            public_read_access = True,
        )


        # result = s3bucket.add_to_resource_policy(_iam.PolicyStatement(
        #     actions = ["s3:GetObject"],
        #     effect = _iam.Effect.DENY,
        #     principals = [ _iam.AnyPrincipal() ],
        #     resources = [ s3bucket.bucket_arn + "/*"  ],
        # ))

        ## access logging TODO
        # s3bucket_policy = s3.BucketPolicy( self, "s3bucket_policy",
        #     bucket = s3bucket,
        #     serverAccessLogsBucket = self.createServerAccessLogsBucket(), )
        # )

        deployment = s3deployment.BucketDeployment(self, "deployStaticWebsite",
            sources = [s3deployment.Source.asset("./assets/website")],
            destination_bucket = s3bucket,
            )


        oai = cloudfront.OriginAccessIdentity(self, 'OriginAccessIdentity')

        cf_distribution = cloudfront.CloudFrontWebDistribution(self, "CognitoManagerWebUI",
            origin_configs=[cloudfront.SourceConfiguration(
                s3_origin_source=cloudfront.S3OriginConfig(
                    s3_bucket_source=s3bucket,
                    origin_access_identity=oai,
                ),
                behaviors=[cloudfront.Behavior(
                    is_default_behavior=True
                )]
            )]
        )


        webui_pool_client = user_pool.add_client("webui-client",
            generate_secret = False,
            auth_flows=cognito.AuthFlow(
                user_password=True,
                user_srp=True,
                admin_user_password=False,
                custom=False,
                ),
            supported_identity_providers = [
                cognito.UserPoolClientIdentityProvider.COGNITO,
                ],

            o_auth=cognito.OAuthSettings(
                flows=cognito.OAuthFlows(
                    authorization_code_grant=True
                ),
                scopes=[cognito.OAuthScope.OPENID],
                #logout_urls=["https://my-app-domain.com/signin"]
                callback_urls=["https://" + cf_distribution.distribution_domain_name ],
            )
        )

        webui_pool_client.apply_removal_policy(CDK_APP_REMOVAL_POLICY)


        # authorizer
        #cognito_auth = apigateway.CfnAuthorizer(
        #     self, "mfaManagerAuthorizer",
        #     name = "mfaManagerAuthorizer",
        #     rest_api_id = manager_api.rest_api_id,
        #     type = 'COGNITO_USER_POOLS',
        #     identity_source='method.request.header.Authorization',
        #     provider_arns =  [ user_pool.user_pool_arn ],
        # )


#
#
#
# // Create an HTTP API
# const api = new sst.Api(this, "Api", {
#   // Secure it with IAM Auth
#   defaultAuthorizationType: sst.ApiAuthorizationType.AWS_IAM,
#   routes: {
#     "GET /private": "src/private.handler",
#     // Make an endpoint public
#     "GET /public": {
#       function: "src/public.handler",
#       authorizationType: sst.ApiAuthorizationType.NONE,
#     },
#   },


#});

# // Allow authenticated users to invoke the API
# auth.attachPermissionsForAuthUsers([api]);
#
