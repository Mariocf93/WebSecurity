using System.ComponentModel.DataAnnotations;

namespace WebSecurity.ViewModels
{
    public class RegisteredUser
    {
        [Required(ErrorMessage = "Please enter a valid username")]
        [Display(Name = "User name")]
        public string UserName { get; set; }

        [Required(ErrorMessage = "Please enter a valid email address")]
        [RegularExpression(@"^([\w\.\-]+)@([\w\-]+)((\.(\w){2,3})+)$",
        ErrorMessage = "This is not a valid email address.")]
        [Display(Name = "Email")]
        public string Email { get; set; }

        [Required(ErrorMessage = "Please enter a valid password")]
        [DataType(DataType.Password)]
        [Display(Name = "Password")]
        public string Password { get; set; }

        [Required(ErrorMessage = "Please re-enter your password")]
        [DataType(DataType.Password)]
        [Display(Name = "Password Confirm")]
        [Compare("Password", ErrorMessage = "The new password and confirmation password do not match.")]
        public string ConfirmPassword { get; set; }
    }
}
