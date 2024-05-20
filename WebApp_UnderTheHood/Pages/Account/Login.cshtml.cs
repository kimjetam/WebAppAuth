using System.ComponentModel.DataAnnotations;
using System.Net;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using WebApp_UnderTheHood.Authorization;

namespace WebApp_UnderTheHood.Pages.Account
{
    public class LoginModel : PageModel
    {
        [BindProperty]
        public Credential Credential { get; set; } = new();

        public void OnGet()
        {
        }

        public async Task<IActionResult> OnPostAsync()
        {
            if (!ModelState.IsValid) return Page();

            // Verify the credential
            if (Credential is not {UserName: "admin", Password: "password"}) return Page();
            
            // creating the security context
            var claims = new List<Claim>
            {
                new(ClaimTypes.Name, "admin"),
                new(ClaimTypes.Email, "admin@mywebsite.com"),
                new("Department", "HR"),
                new("Admin", "true"),
                new("Manager", "true"),
                new("EmploymentDate", "2024-02-01"),
            };

            var identity = new ClaimsIdentity(claims, "MyCookieAuth");
            var claimsPrincipal = new ClaimsPrincipal(identity);

            var authProperties = new AuthenticationProperties
            {
                IsPersistent = Credential.RememberMe
            };

            await HttpContext.SignInAsync("MyCookieAuth", claimsPrincipal, authProperties);

            return RedirectToPage("/Index");
        }
    }
}
