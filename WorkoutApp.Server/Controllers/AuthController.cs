using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Authorization;
using WordGame.Models;
using System.Text.Json;
using System.Linq;
using System.Threading.Tasks;

namespace WorkoutApp.Controllers
{
    [Authorize]
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly SignInManager<IdentityUser> _signInManager;
        private readonly UserManager<IdentityUser> _userManager;

        public AuthController(
            SignInManager<IdentityUser> signInManager,
            UserManager<IdentityUser> userManager 
        ) {
            _signInManager = signInManager;
            _userManager = userManager;
        }

        [AllowAnonymous]
        [HttpPost("register")]
        public async Task<IActionResult> Register(EmailLoginDetails details){
            
            var user = new ApplicationUser {UserName = details.Email, Email = details.Email};

            var result = await _userManager.CreateAsync(user, details.Password).ConfigureAwait(false);

            if(!result.Succeeded) {
                var errors = result.Errors.Select(e => e.Description);                

                return BadRequest(new {errors});
            }

            return Ok(new UserDto {Id = user.Id, UserName = user.UserName});
        }
        

        [AllowAnonymous]
        [HttpPost("login")]
        public async Task<IActionResult> Login(EmailLoginDetails details) {
            var user = await _userManager.FindByEmailAsync(details.Email);

            if(null == user) {
                return BadRequest();
            }

            var result = await _signInManager.PasswordSignInAsync(details.Email, details.Password, false, false)
                                                .ConfigureAwait(false);
                        
            if(!result.Succeeded) {                             
                return Unauthorized();
            }

            return Ok(new UserDto {Id = user.Id, UserName = user.UserName});
        }

        [HttpPost("logout")]
        public async Task<IActionResult> Logout() {
            await _signInManager.SignOutAsync();

            return Ok(new { message = "You've been logged out successfully." });
        }
    }
}