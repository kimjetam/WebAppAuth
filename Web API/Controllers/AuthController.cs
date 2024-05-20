using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Security.Claims;
using System.Text;
using Microsoft.IdentityModel.Tokens;
using Microsoft.Extensions.Configuration;

namespace Web_API.Controllers
{
    [Route("[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly IConfiguration _configuration;

        public AuthController(IConfiguration configuration)
        {
            _configuration = configuration;
        }

        [HttpPost]
        public IActionResult Authenticate([FromBody] Credential credential)
        {
            // Verify the credential
            if (credential is { UserName: "admin", Password: "password" })
            {
                var claims = new List<Claim>
                {
                    new(ClaimTypes.Name, "admin"),
                    new(ClaimTypes.Email, "admin@mywebsite.com"),
                    new("Department", "HR"),
                    new("Admin", "true"),
                    new("Manager", "true"),
                    new("EmploymentDate", "2024-02-01"),
                };

                var expiresAt = DateTime.UtcNow.AddMinutes(10);

                return Ok(new
                {
                    access_token = CreateToken(claims, expiresAt),
                    expires_at = expiresAt,
                });
            }

            ModelState.AddModelError("Unauthorized", "You are not authorized to access the endpoint.");
            return Unauthorized(ModelState);
        }

        private string CreateToken(IEnumerable<Claim> claims, DateTime expireAt)
        {
            var secretKey = Encoding.ASCII.GetBytes(_configuration.GetValue<string>("SecretKey") ?? "");

            // generate the JWT
            var jwt = new JwtSecurityToken(
                claims: claims,
                notBefore: DateTime.UtcNow,
                expires: expireAt,
                signingCredentials: new SigningCredentials(new SymmetricSecurityKey(secretKey), SecurityAlgorithms.HmacSha256Signature));



            return new JwtSecurityTokenHandler().WriteToken(jwt);
        }
        
    }

    public class Credential
    {
        public string UserName { get; set; }
        public string Password { get; set; }
    }
}
