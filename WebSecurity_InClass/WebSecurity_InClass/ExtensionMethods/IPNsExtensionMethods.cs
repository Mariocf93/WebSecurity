using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using WebSecurity_InClass.Models.ViewModels;

namespace WebSecurity_InClass.ExtensionMethods
{
    static public class IPNsExtensionMethods
    {
        static public IEnumerable<IPNVM> ToVM(this IEnumerable<IPN> IPNs)
        {
           return IPNs.Select(i => new IPNVM()
            {
                transID = i.transactionID,
                sessionID = i.custom,
                firstName = i.firstName,
                amount = (double)i.amount,
                lastName = i.lastName,
                transTime =(DateTime)i.txTime,
                totalTixs = (int)i.totalTickets
            });
        }
    }
}