using System.ComponentModel.DataAnnotations;

namespace WebSecurity.ViewModels
{
    public class Login
    {
        [Required(ErrorMessage = "Please enter a valid username")]
        [DataType(DataType.Text,ErrorMessage ="Please enter only text into this field")]
        [Display(Name = "User Name")]
        public string UserName { get; set; }

        [Required(ErrorMessage = "Please enter a valid password")]
        [DataType(DataType.Password)]
        [Display(Name = "Password")]
        public string Password { get; set; }
    }
}
