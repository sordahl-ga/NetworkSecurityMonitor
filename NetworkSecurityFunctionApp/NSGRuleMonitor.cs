/* 
* 2018 Microsoft Corp
* 
* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS “AS IS”
* AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
* THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
* ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE
* FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
* (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
* LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
* HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
* OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
* OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
//Azure Function Support
using Microsoft.Azure.WebJobs;
using Microsoft.Azure.WebJobs.Host;

// Azure Management dependencies
using Microsoft.Rest.Azure.OData;
using Microsoft.Rest.Azure.Authentication;
using Microsoft.Azure.Management.Monitor;
using Microsoft.Azure.Management.Monitor.Models;
using Microsoft.Azure.Management.Network;
using Microsoft.Azure.Management.Network.Models;
using Microsoft.WindowsAzure.Storage;
using Microsoft.WindowsAzure.Storage.Table;
using Microsoft.Azure.ServiceBus;

//Misc
using Newtonsoft.Json;
namespace NetworkSecurityFunctionApp
{
    public static class NSGRuleMonitor
    {
        private static MonitorManagementClient readOnlyClient;
        private static NetworkManagementClient networkClient;
        private static CloudTableClient tableClient;
        [FunctionName("NSGRuleMonitor")]
        //Runs Every 2 minutes looking for changes to network settings across the subscription 
        public static void Run([TimerTrigger("0 */2 * * * *")]TimerInfo myTimer, TraceWriter log)
        {
            log.Info($"NSGRuleMonitor Timer trigger function executed at: {DateTime.Now}");
            //Storage Account Table Access for state information (i.e. LastRun time)
            CloudStorageAccount storageAccount = CloudStorageAccount.Parse(System.Environment.GetEnvironmentVariable("AZURE_STORAGE"));
            tableClient = storageAccount.CreateCloudTableClient();
            //Configuration for connections/operations on Azure Resources
            var tenantId = System.Environment.GetEnvironmentVariable("AZURE_TENANT_ID");
            var clientId = System.Environment.GetEnvironmentVariable("AZURE_CLIENT_ID");
            var secret = System.Environment.GetEnvironmentVariable("AZURE_CLIENT_SECRET");
            var subscriptionId = System.Environment.GetEnvironmentVariable("AZURE_SUBSCRIPTION_ID");
            var storage = System.Environment.GetEnvironmentVariable("AZURE_STORAGE");

            if (new List<string> { tenantId, clientId, secret, subscriptionId }.Any(i => String.IsNullOrEmpty(i)))
            {
                log.Error("Please provide environment variables for AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET and AZURE_SUBSCRIPTION_ID.");
            }
            else
            {
                //Get Management Client Access to Azure for Activity Monitor and Network
                readOnlyClient = AuthenticateWithReadOnlyClient(tenantId, clientId, secret, subscriptionId).Result;
                networkClient = AuthenticateWithNetworkClient(tenantId, clientId, secret, subscriptionId).Result;
                //When did we last check for Network Security Compliance?
                StateInfo lastrunstate = GetOrUpdateLastRunStateInfo().Result;
                StateInfo currentstate = new StateInfo(DateTime.UtcNow.ToString("yyyy'-'MM'-'dd'T'HH':'mm':'ss'Z'"));
                log.Info("NetworkResourceWatcher: Last Ran @" + lastrunstate.LastRunTimeUTC);
                log.Info("NetworkResourceWatcher: Current Time @" + currentstate.LastRunTimeUTC);
                //Start where we left off loading activity events looking for modifications accross the subscription for network resources
                var filter = new ODataQuery<EventData>("eventTimestamp ge '" + lastrunstate.LastRunTimeUTC + "' and eventTimestamp le '" + currentstate.LastRunTimeUTC + "' and resourceProvider eq 'Microsoft.Network'");
                var result = readOnlyClient.ActivityLogs.List(filter);
                //Iterate over events looking for NSG security rule updates
                List<FailedNSGData> nsgfails = new List<FailedNSGData>();
                foreach (EventData d in result)
                {
                    //Avoid duplicates if notification is all set to be sent for operationId
                    if (nsgfails.Any(prod => prod.OperationId == d.OperationId)) continue;
                    if (d.OperationName.Value.Contains("Microsoft.Network/networkSecurityGroups/securityRules/write"))
                    {

                        var split = d.ResourceId.Split('/');
                        var nsgname = split[8];
                        var rulename = split[10];
                        //Retrive the NSG details
                        NetworkSecurityGroup nsg = null;
                        try
                        {
                            nsg = networkClient.NetworkSecurityGroups.Get(d.ResourceGroupName, nsgname);

                        }
                        catch (Exception e)
                        {
                            log.Error("Error Fetching NetworkSecurityGroup: " + e.Message, e);
                            continue;
                        }
                        //Look for compliance failures that our Validator finds on the update/add of this NSG
                        var failures = new List<string>();
                        foreach (SecurityRule rule in nsg.SecurityRules)
                        {
                            if (!NSGRuleValidator.Check(rule, failures))
                            {
                                //This NSG update has failed compliance add it to our list of non-compliance NSGs
                                FailedNSGData data = new FailedNSGData() { OperationName = d.OperationName.Value, OperationId = d.OperationId, Subscription = d.SubscriptionId, ResourceGroup = d.ResourceGroupName, Caller = d.Caller, ResourceId = d.ResourceId, Timestamp = d.EventTimestamp.ToString(), ValidationFailures = failures.ToArray(), NetworkSecuirtyGroupName = nsgname, RuleName = rulename };
                                nsgfails.Add(data);
                            }
                        }

                    }
                    else if (d.OperationName.Value.Contains("Microsoft.Network/networkSecurityGroups/securityRules/delete"))
                    {
                        //Deletion of any NSG causes a notification
                        var split = d.ResourceId.Split('/');
                        var nsgname = split[8];
                        var rulename = split[10];
                        string[] failures = { "NSGSecurityRuleWasDeleted" };
                        FailedNSGData data = new FailedNSGData() { OperationName = d.OperationName.Value, OperationId = d.OperationId, Subscription = d.SubscriptionId, ResourceGroup = d.ResourceGroupName, Caller = d.Caller, ResourceId = d.ResourceId, Timestamp = d.EventTimestamp.ToString(), ValidationFailures = failures.ToArray(), NetworkSecuirtyGroupName = nsgname, RuleName = rulename };
                        nsgfails.Add(data);
                    }
                }
                //Send our Non-Compliant NSGs to a Logic App to handle notification/auditing
                var numsent = QueueNSGFailures(nsgfails, log).Result;
                //Successfully sent our non-compliant list to logic app update the last run date
                var x = GetOrUpdateLastRunStateInfo(currentstate).Result;
                log.Info((numsent < 1) ? "No NSG Rules found out of compliance" : "Found and sent " + numsent + "  NSG rules out of compliance or deleted to action queue");
                log.Info("Last Run Time Updated to: " + currentstate.LastRunTimeUTC);

            }
        }
        private static async Task<StateInfo> GetOrUpdateLastRunStateInfo(StateInfo state = null)
        {
            CloudTable stateTable = tableClient.GetTableReference("networkMonitorState");
            await stateTable.CreateIfNotExistsAsync();

            if (state == null)
            {
                TableOperation retrieveOperation = TableOperation.Retrieve<StateInfo>("StateInfo", "LastRun");
                // Execute the retrieve operation.
                var retrievedResult = await stateTable.ExecuteAsync(retrieveOperation);
                if (retrievedResult.Result != null)
                {
                    return (StateInfo)retrievedResult.Result;
                }
                return new StateInfo(DateTime.UtcNow.ToString("yyyy'-'MM'-'dd'T'HH':'mm':'ss'Z'"));
            }
            else
            {
                // Create the TableOperation that inserts the customer entity.
                TableOperation insertOperation = TableOperation.InsertOrReplace(state);
                // Execute the insert operation.
                await stateTable.ExecuteAsync(insertOperation);
                return state;
            }
        }
        public static async Task<int> QueueNSGFailures(List<FailedNSGData> fails, TraceWriter log)
        {
            int sentmessages = 0;

            IQueueClient queueClient = new QueueClient(System.Environment.GetEnvironmentVariable("AZURE_SB_QUEUE_CONNECT"), System.Environment.GetEnvironmentVariable("AZURE_SB_QUEUE"));
            foreach (FailedNSGData data in fails)
            {
                try
                {
                    // Create a new message to send to the queue
                    string messageBody = JsonConvert.SerializeObject(data, Formatting.Indented);
                    var message = new Message(Encoding.UTF8.GetBytes(messageBody));

                    // Write the body of the message to the console
                    log.Info($"Sending message: {messageBody} to queue {queueClient.QueueName}");

                    // Send the message to the queue
                    await queueClient.SendAsync(message);
                    sentmessages++;
                }
                catch (Exception exception)
                {
                    log.Error($"{DateTime.Now} :: Exception: {exception.Message}", exception);
                }

            }
            return sentmessages;
           
        }
        private static async Task<MonitorManagementClient> AuthenticateWithReadOnlyClient(string tenantId, string clientId, string secret, string subscriptionId)
        {
            // Build the service credentials and Monitor client
            var serviceCreds = await ApplicationTokenProvider.LoginSilentAsync(tenantId, clientId, secret);
            var monitorClient = new MonitorManagementClient(serviceCreds);
            monitorClient.SubscriptionId = subscriptionId;

            return monitorClient;
        }
        private static async Task<NetworkManagementClient> AuthenticateWithNetworkClient(string tenantId, string clientId, string secret, string subscriptionId)
        {
            // Build the service credentials and Monitor client
            var serviceCreds = await ApplicationTokenProvider.LoginSilentAsync(tenantId, clientId, secret);
            var monitorClient = new NetworkManagementClient(serviceCreds);
            monitorClient.SubscriptionId = subscriptionId;

            return monitorClient;
        }

    }
}
