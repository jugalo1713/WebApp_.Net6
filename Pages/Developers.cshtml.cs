using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace WebApp_.Net6.Pages
{
    [Authorize(Policy = "DevelopersOnly")]
    public class DevelopersModel : PageModel
    {
        public void OnGet()
        {
        }
    }
}
