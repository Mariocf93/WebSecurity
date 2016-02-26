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
                email = i.buyerEmail,
                amount = (double)i.amount,
                paymentStat = i.paymentStatus
            });
        }
    }
}