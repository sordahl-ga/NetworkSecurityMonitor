# Network Security Monitor POC

This is a Azure Function Application that monitors for network changes across subscriptions. It runs defined network compliance
validators for example ports, ipaddress, etc... to ensure compliance with network policy on a schedule.  Non-compliant alerts are 
sent to a service bus queue for further processing and action.

The monitor is looking for changes to NSG Rules on a user defined frequency, any alteration or removal of an NSG causes it
to be inspected for compliance and if compliance validation fails it is sent to a service bus queue for processing or action.

There is also a complementary logic app that listens on the service bus queue and has the action to email a designated responder to
investigate the complinace issue.


## Getting Started

1. [Create a resource group in the subscription you want to monitor](https://docs.microsoft.com/en-us/azure/azure-resource-manager/resource-group-portal#manage-resource-groups)
2. [In this group create an Azure Service Bus](https://docs.microsoft.com/en-us/azure/service-bus-messaging/service-bus-dotnet-get-started-with-queues#1-create-a-namespace-using-the-azure-portal)
3. [Get the Connection String for the Service Bus.](https://docs.microsoft.com/en-us/azure/service-bus-messaging/service-bus-dotnet-get-started-with-queues#obtain-the-management-credentials)
     This string value will go into the AZURE_SB_QUEUE_CONNECT setting in app settings and local.settings
4. [Create a queue in the Service Bus.](https://docs.microsoft.com/en-us/azure/service-bus-messaging/service-bus-dotnet-get-started-with-queues#2-create-a-queue-using-the-azure-portal) The name of the queue will go into the AZURE_SB_QUEUE setting in app settings and local.settings 
5. [In the same group create a general purpose storage account](https://docs.microsoft.com/en-us/azure/storage/common/storage-create-storage-account?toc=%2fazure%2fstorage%2fblobs%2ftoc.json#create-a-storage-account)
6. In Azure AD register an application
	
    * Go to the Azure Portal (http://portal.azure.com).  On the left-hand Nav bar, choose Azure Active Directory  (you may have to click on “more services” or search for it)
     
    * Make sure the directory shown at the top of the blade is the one in which you want to run your application  (the one you use to log into the portal and manage your IoT Hub)
     
    * On the Azure Active Directory blade, choose “App registrations”
    
    * Click on “New application registration.”  On the “Create” blade
        * Enter a name for your application (which must be unique within the AAD instance).
        * For application type, leave the default of “Web app / API”
        * For Sign-on URL, enter any validly formed URL (i.e. http://fakeurl.com).  We won’t use this URL, as this is not a ‘real’ application
    * Once created, navigate to your new application (you may have to search for it).  One the main blade for your application, copy the Application ID and hang onto it and place it in the AZURE_CLIENT_ID app setting.
     
    * Click on “All settings” and then click “Keys”. Under the Passwords section, we need to create a new application password
        * Under Key description, enter a descriptive name for your key
        * Under expiration, enter your desired expiration timeframe (just remember it, if the password expires, the solution will fail to authenticate and stop working)
        * Click “Save” --   DO NOT CLOSE THE BLADE YET
        * After you click Save, the password “Value” should have been generated.  Copy and save this value somewhere safe and place it in the AZURE_CLIENT_SECRET appsetting  You’ll need it later and you *cannot retrieve it once you leave this blade*.    (if you happen to lose it, you can return to this screen and create another password).  Close the Keys blade
        
    * Now we need to give that application permission to our subscription.
        * Navigate in the Azure Portal to your chosen subscription. In settings, click on “Access Control (IAM)”.  Click the “Add” button
            * Under Role, choose Reader
            * Under “Assign Access to”, leave the default of “Azure AD user, group, or application”
            * Under “Select”, search for your application you created earlier (by name)
            * Select your application from the search results and choose Save
            * You should now see that the application has reader access permissions to your subscription
            
    * To authenticate our function app, we also need our subscription and tenant Ids.
        * To get your subscription id, in the Azure Portal, on the left-hand nav bar choose “subscriptions”, find the subscription that you are monitoring NSG changes for, and copy the Id into the AZURE_SUBSCRIPTION_ID app setting
        * Getting the TenantId is a little trickier.  A quick web search will show you command line and powershell ways to do it.  However, from the Azure Portal, you can click on the “help” icon (the “?” in the upper right) and choose Show Diagnostics.  This will download a JSON file.  In that JSON file, you can do a search for “TenantId” and find it. This value goes in the AZURE_TENANT_ID app setting.

7. Clone this repository and build it in Visual Studio 2017 (Make sure the [Azure Functions Tools](https://docs.microsoft.com/en-us/azure/azure-functions/functions-develop-vs) are installed)

8. Add the following App Settings to your local.settings.json file using the keys/connection strings as specified above
```
{
    "IsEncrypted": false,
  "Values": {
    "AzureWebJobsStorage": "UseDevelopmentStorage=true",
    "AzureWebJobsDashboard": "UseDevelopmentStorage=true",
    "AZURE_TENANT_ID": "your teneant id",
    "AZURE_CLIENT_ID": "your client id",
    "AZURE_CLIENT_SECRET": "your client secret",
    "AZURE_SUBSCRIPTION_ID": "your subscription",
    "AZURE_STORAGE": "your storage account connection string",
    "AZURE_SB_QUEUE_CONNECT": "your service bus connection",
    "AZURE_SB_QUEUE": "your queue name"
  }
}
```
8. That's it you can now run this function app locally for debugging, and it will begin to enqueue any changes that are made to NSGs in your subscriptions that are out
   of compliance.  You can change parameters and add validators as needed for your needs.

9. You can add hooks to the queue for notification/action processing.  For example the [Azure Logic Application Flow](https://docs.microsoft.com/en-us/azure/logic-apps/quickstart-create-first-logic-app-workflow) below listens for queued messages
   then sends an email with details in the body of the NSG non-compliance:
```
{
    "$connections": {
        "value": {
            "office365": {
                "connectionId": "/subscriptions/{sub id}/resourceGroups/securitypoc/providers/Microsoft.Web/connections/office365",
                "connectionName": "office365",
                "id": "/subscriptions/{sub id}/providers/Microsoft.Web/locations/eastus/managedApis/office365"
            },
            "servicebus": {
                "connectionId": "/subscriptions/{sub id}/resourceGroups/securitypoc/providers/Microsoft.Web/connections/servicebus",
                "connectionName": "servicebus",
                "id": "/subscriptions/{sub id}/providers/Microsoft.Web/locations/eastus/managedApis/servicebus"
            }
        }
    },
    "definition": {
        "$schema": "https://schema.management.azure.com/providers/Microsoft.Logic/schemas/2016-06-01/workflowdefinition.json#",
        "actions": {
            "Send_an_email": {
                "inputs": {
                    "body": {
                        "Body": "@base64ToString(triggerBody()?['ContentData'])",
                        "Subject": "NSG Compliance Alert for subscription @{triggerBody()?['Subscription']}",
                        "To": "email@company.com"
                    },
                    "host": {
                        "connection": {
                            "name": "@parameters('$connections')['office365']['connectionId']"
                        }
                    },
                    "method": "post",
                    "path": "/Mail"
                },
                "runAfter": {},
                "type": "ApiConnection"
            }
        },
        "contentVersion": "1.0.0.0",
        "outputs": {},
        "parameters": {
            "$connections": {
                "defaultValue": {},
                "type": "Object"
            }
        },
        "triggers": {
            "When_a_message_is_received_in_a_queue_(auto-complete)": {
                "inputs": {
                    "host": {
                        "connection": {
                            "name": "@parameters('$connections')['servicebus']['connectionId']"
                        }
                    },
                    "method": "get",
                    "path": "/@{encodeURIComponent(encodeURIComponent('{queue name}'))}/messages/head",
                    "queries": {
                        "queueType": "Main"
                    }
                },
                "recurrence": {
                    "frequency": "Minute",
                    "interval": 1
                },
                "type": "ApiConnection"
            }
        }
    }
}
``` 
10. You can publish the Function Application to Azure into the same resource group using the Visual Studio Publish tool. Make sure your app settings from local.settings are entered in the function app settings in VS Publish profile or 
    via the portal. 

## Authors

* **Steven Ordahl** - Microsoft HLS Apps and Infrastructure Cloud Architect
