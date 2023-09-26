using AngularAuthAPI.DatabaseDb;
using AngularAuthAPI.Helpers;
using AngularAuthAPI.Models;
using AngularAuthAPI.UtilityServices;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace AngularAuthAPI.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class UserController : ControllerBase
    {
        private readonly UserDbContext _userDbContext;
        private readonly IConfiguration _configuration;
        private readonly IEmailService _emailService;
        public UserController(UserDbContext userDbContext, IConfiguration configuration,IEmailService emailService)
        {
            _userDbContext = userDbContext;
            _configuration = configuration;
            _emailService = emailService;
        }

        [HttpPost("authenticate")]
        public async Task<IActionResult> Authenticate(LoginModel user)
        {
            if (user == null)
            {
                return BadRequest();
            }
            var userFromDb = await _userDbContext.Users.FirstOrDefaultAsync(a => a.UserName == user.Username);
            if (user == null)
            {
                return NotFound();
            }
            if (!PasswordHasher.VerifyPassword(user.Password, userFromDb.Password))
            {
                return BadRequest("Password is incorrect");
            }
            userFromDb.Token = CreateJwt(userFromDb);
            var refreshToken = CreateRefreshToken();
            var expireTIME = DateTime.Now.AddDays(1);
            userFromDb.RefreshTokenExpiryTime = expireTIME;
            userFromDb.RefreshToken = refreshToken;

            _userDbContext.SaveChanges();
            return Ok(new TokenApiDto()
            {
                AccessToken = userFromDb.Token,
                RefreshToken = refreshToken
            });


        }
        [HttpPost("register")]
        public async Task<IActionResult> RegisterUser(User user)
        {
            if (user == null)
            {
                return BadRequest();
            }
            bool userNameExists = _userDbContext.Users.AnyAsync(a => a.UserName.Equals(user.UserName)).Result;
            if (userNameExists)
            {
                return BadRequest("UserName Already Exists");
            }
            bool EmailExists = _userDbContext.Users.AnyAsync(a => a.Email.Equals(user.Email)).Result;
            if (EmailExists)
            {
                return BadRequest("Email Already Exists");
            }
            user.Password = PasswordHasher.PasswordHash(user.Password);
            await _userDbContext.Users.AddAsync(user);
            await _userDbContext.SaveChangesAsync();

            return Ok(new
            {
                Message = "User Registered Successfully............."
            });
        }
        [HttpPost("refresh")]
        public async Task<IActionResult> RefreshToken(TokenApiDto tokenApiDto)
        {
            if (tokenApiDto == null)
            {
                return BadRequest("");
            }
            string accessToken = tokenApiDto.AccessToken;
            string refreshToken = tokenApiDto.RefreshToken;
            var principal = GetPrincipalfromExpiredToken(accessToken);
            var username = principal.Claims.FirstOrDefault(s => s.Type == "name").Value;
            var user = await _userDbContext.Users.FirstOrDefaultAsync(s => s.UserName == username);
            if (user == null || user.RefreshToken != refreshToken) //|| user.RefreshTokenExpiryTime<=DateTime.Now
            {
                return BadRequest();
            }
            accessToken = CreateJwt(user);
            refreshToken = CreateRefreshToken();
            user.Token= accessToken;
            user.RefreshToken= refreshToken;
            user.RefreshTokenExpiryTime = DateTime.Now.AddDays(1);
            await _userDbContext.SaveChangesAsync();
            return Ok(new TokenApiDto()
            {
                AccessToken = accessToken,
                RefreshToken = refreshToken
            });
        }
        [HttpGet]
        [Authorize]
        public ActionResult<List<String>> GetStrings()
        {
            return Ok(new List<string>() { "sreeni", "krishna" });
        }
        [HttpPost("send-reset-email/{email}")]
        public async Task<IActionResult> SendEmail(string email)
        {
            var user = _userDbContext.Users.FirstOrDefault(a => a.Email.Equals(email));
            if (user == null)
            {
                return NotFound(new
                {
                    Message = "Mail Doesn't Exist"
                }) ; 
            }
            var emailTokenBytes = RandomNumberGenerator.GetBytes(64);
            var emailToken=Convert.ToBase64String(emailTokenBytes);
            user.ResetPasswordToken = emailToken;
            user.ResetPasswordTokenExpiryTime= DateTime.Now.AddMinutes(15);
            var from = _configuration["EmailSettings:From"];
            var emailModel = new EmailModel(email, "Reset Password!!", EmailBody.EmailStringBody(email, emailToken));
            _emailService.SendEmail(emailModel);
            _userDbContext.Entry(user).State = EntityState.Modified;
            _userDbContext.SaveChangesAsync();
            return Ok(new
            {
                StatusCode=200,
                Message = "Message Sent!"
            }) ;
        }
        [HttpPost("reset-password")]
        public async Task<IActionResult> ResetPassword(ResetPasswordDto resetPassword)
        {
            var newToken = resetPassword.EmailToken.Replace(" ", "+");
            var user= _userDbContext.Users.FirstOrDefault(e=>e.Email.Equals(resetPassword.Email));
            if (user == null)
            {
                return NotFound(new
                {
                    StatusCode=404,
                    Message = "Mail Doesn't Exist"
                });
            }
            var tokenCode = user.ResetPasswordToken;
            DateTime resetPasswordExpiry = user.ResetPasswordTokenExpiryTime;
            if(tokenCode!=resetPassword.EmailToken || resetPasswordExpiry<DateTime.Now)
            {
                return BadRequest(new
                {
                    StatusCode = 500,
                    Message = "Invalid Reset Password Link"
                });
            }
            user.Password=PasswordHasher.PasswordHash(resetPassword.NewPassword);
            _userDbContext.Entry(user).State=EntityState.Modified;
            _userDbContext.SaveChangesAsync();
            return Ok(new
            {
                StatusCode = 200,
                Message = "Password Rest Successsfully........"
            });
        }
        private string CreateJwt(User user)
        {
            /*var jwttokenhandler = new JwtSecurityTokenHandler();
            var key = Encoding.UTF8.GetBytes(_configuration["JWT:Secret"]);
            List<Claim> claims = new List<Claim>()
            {
                new Claim(ClaimTypes.Name, user.UserName),
                new Claim(ClaimTypes.Role, user.Role),
            };
            var identity = new ClaimsIdentity(claims);

            var credentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256);
            var tokenDescriptor = new SecurityTokenDescriptor()
            {
                Subject = identity,
                SigningCredentials = credentials,
                Expires = DateTime.Now.AddDays(1)
            };*/

            /*var token = jwttokenhandler.CreateToken(tokenDescriptor);
            return jwttokenhandler.WriteToken(token);*/

            var AuthClaims = new List<Claim>()
                {
                    new Claim("name",user.UserName),
                    new Claim(JwtRegisteredClaimNames.Jti,Guid.NewGuid().ToString()),
                    new Claim(ClaimTypes.Role, user.Role)
                };

            /*foreach (var userRole in userRoles)
            {
                AuthClaims.Add(new Claim(ClaimTypes.Role, userRole));
            }*/
            var AuthSignInKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JWT:Secret"]));
            var token = new JwtSecurityToken(
                issuer: _configuration["JWT:ValidIssuer"],
                audience: _configuration["JWT:ValidAudience"],
                expires: DateTime.Now.AddSeconds(20),
                claims: AuthClaims,
                signingCredentials: new SigningCredentials(AuthSignInKey, SecurityAlgorithms.HmacSha256)
                );

            var newAccessToken = new JwtSecurityTokenHandler().WriteToken(token);
            return newAccessToken;
            
        }
        private string CreateRefreshToken()
        {
            var RandomNumber = RandomNumberGenerator.GetBytes(64);
            string refreshToken = Convert.ToBase64String(RandomNumber);
            var tokenInUse = _userDbContext.Users.Any(x => x.RefreshToken == refreshToken);
            if (tokenInUse)
            {
                return CreateRefreshToken();
            }
            return refreshToken;
        }
        private ClaimsPrincipal GetPrincipalfromExpiredToken(string token)
        {
            var tokenValidationParameters = new TokenValidationParameters()
            {
                /*ValidateIssuer = true,
                ValidateAudience = true,
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JWT:Secret"])),
                ValidateLifetime = false*/
                ValidateIssuer = true,
                ValidateAudience = true,
                ValidAudience = _configuration["JWT:ValidAudience"],
                ValidIssuer = _configuration["JWT:ValidIssuer"],
                ValidateLifetime = false,
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JWT:Secret"])),
                ClockSkew = TimeSpan.Zero

            };
            var tokenHandler = new JwtSecurityTokenHandler();
            SecurityToken securityToken;
            var principal = tokenHandler.ValidateToken(token, tokenValidationParameters, out securityToken);
            var jwtSecutiryToken = securityToken as JwtSecurityToken;
            if (jwtSecutiryToken == null || !jwtSecutiryToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256))
            {
                throw new SecurityTokenException("This is not a valid token");
            }
            return principal;

        }
    }
}