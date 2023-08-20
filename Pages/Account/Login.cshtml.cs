using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.ComponentModel.DataAnnotations;
using System.Security.Claims;

namespace WebApp_.Net6.Pages.Account
{
    public class LoginModel : PageModel
    {
        [BindProperty]
        public Credential Credentials { get; set; }
        
        public void OnGet()
        {
        }

        public async Task<IActionResult> OnPostAsync()
        {
            if (!ModelState.IsValid) return Page();

            //1 verify credential
            if(Credentials.UserName == "jugalo1713" && Credentials.Password == "123")
            {

                //create security context
                var claims = new List<Claim>
                {
                    new Claim(ClaimTypes.Name, "jugalo1713"),
                    new Claim(ClaimTypes.Email, "julianlondono@outlook.com"),
                    new Claim("Department", "HR"),
                    new Claim("Admin", "true"),
                    new Claim("Developer", "true"),
                    new Claim("EmploymentDate", "2021-08-16"),
                };

                var identity = new ClaimsIdentity(claims, "MyCookieAuthJulian");
                var principal = new ClaimsPrincipal(identity);
                var authenticationProperties = new AuthenticationProperties
                {
                    IsPersistent = Credentials.RememberMe
                };

                await HttpContext.SignInAsync("MyCookieAuthJulian", principal, authenticationProperties);

                return RedirectToPage("/Index");
            }

            return Page();
        }

        public class Credential
        {
            [Required]
            [Display(Name ="User Name")]
            public string UserName { get; set; }
            [Required]
            [DataType(DataType.Password)]
            public string Password { get; set; }

            [Display(Name = "Remember me")]
            public bool RememberMe { get; set; }

        }
    }
}
