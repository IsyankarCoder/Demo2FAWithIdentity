using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System.Text;

namespace Demo2FAWithIdentity.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class AccountController(UserManager<IdentityUser> userManager, IConfiguration configuration)
        : ControllerBase
    {
        private readonly IConfiguration _configuration = configuration;

        private async Task<IdentityUser?> GetUser(string email)
        {
            return await userManager.FindByEmailAsync(email);
        }

        [HttpPost("register/{email}/{password}")]
        public async Task<IActionResult> Register(string email, string password)
        {
            await userManager.CreateAsync(new IdentityUser
            {
                UserName = email,
                Email = email,
                PasswordHash = password
            }, password);

            await userManager.SetTwoFactorEnabledAsync(
               await GetUser(email), true);

            return Ok("User registered");
        }


        [HttpPost("login/{email}/{password}")]
        public async Task<IActionResult> Login(string email, string password)
        {
            var user = await GetUser(email);
            if (user == null)
                return Unauthorized("Invalid email or password");
            var isPasswordValid = await userManager.CheckPasswordAsync(user, password);
            if (!isPasswordValid)
                return Unauthorized("Invalid email or password");
            if (await userManager.GetTwoFactorEnabledAsync(user))
            {
                var token = await userManager.GenerateTwoFactorTokenAsync(
                    user, TokenOptions.DefaultEmailProvider);
                // In a real application, send the token via email/SMS
                // return Ok(new { Message = "2FA required", Token = token });
                return Ok(new[] { SendMail(user, token), token });
            }
            return Ok("Login successful without 2FA");
        }


        private object? SendMail(IdentityUser? identityUser, string token)
        {
            StringBuilder emailBodyBuilder = new StringBuilder();

            emailBodyBuilder.AppendLine("<html>");
            emailBodyBuilder.AppendLine("<style>");
            emailBodyBuilder.AppendLine("body { font-family: Arial, sans-serif; }");
            emailBodyBuilder.AppendLine("h1 { color: #333; }");
            emailBodyBuilder.AppendLine("p { font-size: 14px; }");
            emailBodyBuilder.AppendLine("</style>");
            emailBodyBuilder.AppendLine("<body>");
            emailBodyBuilder.AppendLine($"<p>Dear {identityUser?.UserName},</p>");
            emailBodyBuilder.AppendLine($"<p class='code'>Your two-factor authentication (2FA) token is: {token} </p>");

            emailBodyBuilder.AppendLine("</body>");
            emailBodyBuilder.AppendLine("</html>");

            string emailBody = emailBodyBuilder.ToString();

            var emailMimeKit = new MimeKit.MimeMessage();
            emailMimeKit.From.Add(MimeKit.MailboxAddress.Parse("leann.nicolas@ethereal.email"));
            emailMimeKit.To.Add(MimeKit.MailboxAddress.Parse(identityUser?.Email ?? ""));
            emailMimeKit.Subject = "Your 2FA Token";
            emailMimeKit.Body = new MimeKit.TextPart(MimeKit.Text.TextFormat.Html)
            {
                Text = emailBody
            };

            using var smtp = new MailKit.Net.Smtp.SmtpClient();

            //smtp.ethereal.com
            smtp.Connect("smtp.ethereal.email", 587, MailKit.Security.SecureSocketOptions.StartTls);
            smtp.Authenticate("leann.nicolas@ethereal.email", "K5ac331DQF6sUvuG2x");
            smtp.Send(emailMimeKit);
            smtp.Disconnect(true);
            //smtp.Dispose();
            return "2FA verification code ,kindly check and verfiy";
        }


        [HttpPost("verify2fa/{email}/{token}")]
        public async Task<IActionResult> Verify2FA(string email, string token)
        {
            var user = await GetUser(email);
            if (user == null)
                return Unauthorized("Invalid email or token");
            var isTokenValid = await userManager.VerifyTwoFactorTokenAsync(
                user, TokenOptions.DefaultEmailProvider, token);
            if (!isTokenValid)
                return Unauthorized("Invalid email or token");

            return Ok(new[] { "Login successful with 2FA",
                              GenerateToken(await GetUser(email))
                             });
        }


        private string GenerateToken(IdentityUser? user)
        {
            var tokenHandler = new System.IdentityModel.Tokens.Jwt.JwtSecurityTokenHandler();
            var key = Encoding.UTF8.GetBytes(_configuration.GetValue<string>("Jwt:Key")!);

            var tokenDescriptor = new Microsoft.IdentityModel.Tokens.SecurityTokenDescriptor
            {
                Subject = new System.Security.Claims.ClaimsIdentity(new[]
                {
                new System.Security.Claims.Claim(System.Security.Claims.ClaimTypes.Name, user?.UserName ?? ""),
                new System.Security.Claims.Claim(System.Security.Claims.ClaimTypes.Email, user?.Email ?? "")
            }),
                Expires = DateTime.UtcNow.AddHours(1),
                SigningCredentials = new Microsoft.IdentityModel.Tokens.SigningCredentials(
                    new Microsoft.IdentityModel.Tokens.SymmetricSecurityKey(key),
                    Microsoft.IdentityModel.Tokens.SecurityAlgorithms.HmacSha256Signature)
            };
            var token = tokenHandler.CreateToken(tokenDescriptor);
            return tokenHandler.WriteToken(token);
        }
    }
}