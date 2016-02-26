using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.ComponentModel.DataAnnotations;

namespace WebSecurity_InClass.Models.ViewModels
{
    public class IPNVM
    {
        [Display(Name = "TransactionID")]
        public string transID { get; set; }
        [Display(Name = "Session ID")]
        public string sessionID { get; set; }
        [Display(Name = "Buyer Email")]
        public string email { get; set; }
        [Display(Name = "Amount Paid")]
        public double amount { get; set; }
        [Display(Name = "Status of Pay")]
        public string paymentStat { get; set; }
    }
}