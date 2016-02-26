using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.ComponentModel.DataAnnotations;

namespace WebSecurity_InClass.Models.ViewModels
{
    public class IPNVM
    {
        [Display(Name = "Transaction Time")]
        public DateTime transTime { get; set; }
        [Display(Name = "First Name")]
        public string firstName { get; set; }
        [Display(Name = "Last Name")]
        public string lastName { get; set; }
        [Display(Name = "Session ID")]
        public string sessionID { get; set; }
        [Display(Name = "TransactionID")]
        public string transID { get; set; }
        [Display(Name = "Total Tickets")]
        public int totalTixs { get; set; }
        [Display(Name = "Amount Paid")]
        [DataType(DataType.Currency)]
        public double amount { get; set; }
    }
}