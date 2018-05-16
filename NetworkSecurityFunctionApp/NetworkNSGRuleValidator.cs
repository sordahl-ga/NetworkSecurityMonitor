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
using Microsoft.Azure.Management.Network.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace NetworkSecurityFunctionApp
{
    public static class NSGRuleValidator
    {
        private static Predicate<SecurityRule>[] _checks = new Predicate<SecurityRule>[]
        {
                NSGRuleValidator.IsNotRestrictedPorts,
                NSGRuleValidator.IsNotRestrictedIps
                
        };

        public static bool Check(SecurityRule sg, ICollection<string> failedPredicateNames)
        {

            var failed = false;
            foreach (var check in _checks)
            {
                if (!check(sg))
                {
                    failedPredicateNames.Add(check.Method.Name);
                    failed = true;
                }
            }
            return !failed;
        }

        public static bool IsNotRestrictedPorts(SecurityRule rule)
        {
           
                var portrangepass = true;
                if (rule.DestinationPortRange != null)
                {
                    var str = rule.DestinationPortRange.Split('-');
                    portrangepass = !(str.Any("1433".Contains));

                } else if (rule.DestinationPortRanges !=null)
                {
                    foreach(string str1 in rule.DestinationPortRanges)
                    {
                        var str = str1.Split('-');
                        if (str.Any("1433".Contains))
                        {
                            portrangepass = false;
                            break;
                        }
                    }
                }
                if (rule.Direction.ToLower().Equals("inbound") && !portrangepass && rule.Access.ToLower().Equals("allow"))
                {
                    return false;
                }
            
            return true;
        }


        public static bool IsNotRestrictedIps(SecurityRule rule)
        {
                if (rule.Direction.ToLower().Equals("outbound") && rule.DestinationAddressPrefix.Equals("Internet") && rule.Access.ToLower().Equals("Allow"))
                {
                    return false;
                }
           
            return true;
        }

      
    }

    
}
