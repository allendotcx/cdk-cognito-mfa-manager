import aws_cdk as core
import aws_cdk.assertions as assertions

from cognito_mfa_manager.cognito_mfa_manager_stack import CognitoMfaManagerStack

# example tests. To run these tests, uncomment this file along with the example
# resource in cognito_mfa_manager/cognito_mfa_manager_stack.py
def test_sqs_queue_created():
    app = core.App()
    stack = CognitoMfaManagerStack(app, "cognito-mfa-manager")
    template = assertions.Template.from_stack(stack)

#     template.has_resource_properties("AWS::SQS::Queue", {
#         "VisibilityTimeout": 300
#     })
