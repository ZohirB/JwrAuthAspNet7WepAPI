using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using JWTAuthAspNet7WepAPI.Core.Entities;
using JWTAuthAspNet7WepAPI.Core.OtherObjects;
using JWTAuthAspNet7WepAPI.Dtos;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;

namespace JWTAuthAspNet7WepAPI.Controllers;


[Route("api/[controller]")]
[ApiController]

public class AuthController : ControllerBase
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly RoleManager<IdentityRole> _roleManager;
    private readonly IConfiguration _configuration;
    public AuthController(UserManager<ApplicationUser> userManager, RoleManager<IdentityRole> roleManager, IConfiguration configuration)
    {
        _userManager = userManager;
        _roleManager = roleManager;
        _configuration = configuration;
    }
    
    //Rote For seeding My roles to DB
    [HttpGet]
    [Route("seed-roles")]
    public async Task<IActionResult> SeedRoles()
    {
        bool isAppRoleExists = await _roleManager.RoleExistsAsync(StaticUserRoles.APP_USER);
        bool isDashRoleExists = await _roleManager.RoleExistsAsync(StaticUserRoles.Dash_USER);
        bool isAdminRoleExists = await _roleManager.RoleExistsAsync(StaticUserRoles.ADMIN);
        bool isSuperAdminRoleExists = await _roleManager.RoleExistsAsync(StaticUserRoles.SUPER_ADMIN);

        if (isAppRoleExists && isDashRoleExists && isAdminRoleExists && isSuperAdminRoleExists)
        {
            return Ok("role seeding is already done");
        }
        
        await _roleManager.CreateAsync(new IdentityRole(StaticUserRoles.APP_USER));
        await _roleManager.CreateAsync(new IdentityRole(StaticUserRoles.Dash_USER));
        await _roleManager.CreateAsync(new IdentityRole(StaticUserRoles.ADMIN));
        await _roleManager.CreateAsync(new IdentityRole(StaticUserRoles.SUPER_ADMIN));

        return Ok("role seeding Done Successfully");
    }

    [HttpPost]
    [Route("register")]
    public async Task<IActionResult> Register([FromBody] RegisterDto registerDto)
    {
        var isExistUser = await _userManager.FindByNameAsync(registerDto.UserName);
        if (isExistUser != null)
            return BadRequest("UserName Already Exists");

        ApplicationUser newUser = new ApplicationUser()
        {
            FirstName = registerDto.FisrtName,
            LastName = registerDto.LastName,
            Email = registerDto.LastName,
            UserName = registerDto.UserName,
            SecurityStamp = Guid.NewGuid().ToString(),
        };
        var creatUserResult = await _userManager.CreateAsync(newUser, registerDto.Password);
        if (!creatUserResult.Succeeded)
        {
            var errorString = "User Creation Failed Because: ";
            foreach (var error in creatUserResult.Errors)
            {
                errorString += " # " + error.Description;
            }

            return BadRequest(errorString);
        }
        await _userManager.AddToRoleAsync(newUser, StaticUserRoles.APP_USER);  
        return Ok("User Created Successfully");
    }

    [HttpPost]
    [Route("login")]
    public async Task<IActionResult> Login([FromBody] LoginDto loginDto)
    {
        var user = await _userManager.FindByNameAsync(loginDto.UserName);
        if (user is null)
            return Unauthorized("Invalid Credentials");

        var isPasswordCorrect = await _userManager.CheckPasswordAsync(user, loginDto.Password);
        if (!isPasswordCorrect)
            return Unauthorized("Invalid Credentials");
        var userRoles = await _userManager.GetRolesAsync(user);
        var authClaims = new List<Claim>
        {
            new Claim(ClaimTypes.Name, user.UserName),
            new Claim(ClaimTypes.NameIdentifier, user.Id),
            new Claim("JWTID", Guid.NewGuid().ToString()),
            new Claim("FirstName", user.FirstName),
            new Claim("LastName", user.LastName),
        };
        foreach (var userRole in userRoles)
        {
            authClaims.Add(new Claim(ClaimTypes.Role, userRole));
        }

        var token = GenerateNewJsonWebToken(authClaims);
        return Ok(token);
    }

    private string GenerateNewJsonWebToken(List<Claim> claims)
    {
        var authSecret = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JWT:Secret"]));
        var tokenObject = new JwtSecurityToken(
            issuer: _configuration["JWT:ValidIssuer"],
            audience: _configuration["JWT:ValidAudience"],
            expires: DateTime.Now.AddHours(1),
            claims: claims,
            signingCredentials: new SigningCredentials(authSecret, SecurityAlgorithms.HmacSha256)
        );
        string token = new JwtSecurityTokenHandler().WriteToken(tokenObject);
        return token;
    }

    [HttpPost]
    [Route("MakeAdminUser")]
    [Authorize(Roles = StaticUserRoles.SUPER_ADMIN)]
    public async Task<IActionResult> MakeAdmin ([FromBody] UpdatePermissionDto updatePermissionDto)
    {
        var user = await _userManager.FindByNameAsync(updatePermissionDto.UserName);
        if (user is null)
            return BadRequest("invalid user name!");
        
        
        await _userManager.AddToRoleAsync(user, StaticUserRoles.ADMIN);
        return Ok("User is now an ADMIN");
    }
    
    [HttpPost]
    [Route("MakeDashUser")]
    [Authorize(Roles = StaticUserRoles.SUPER_ADMIN + "," + StaticUserRoles.ADMIN)]
    public async Task<IActionResult> MakeDashUser ([FromBody] UpdatePermissionDto updatePermissionDto)
    {
        var user = await _userManager.FindByNameAsync(updatePermissionDto.UserName);
        if (user is null)
            return BadRequest("invalid user name!");
        await _userManager.AddToRoleAsync(user, StaticUserRoles.Dash_USER);
        return Ok("User is now an OWNER");
    }

    [HttpDelete]
    [Route("DeleteUser")]
    [Authorize(Roles = StaticUserRoles.SUPER_ADMIN)]
    public async Task<IActionResult> DeleteUser(string userName)
    {
        var deleteUser = await _userManager.FindByNameAsync(userName);
        if (deleteUser == null)
        {
            return NotFound(value: "No User found by givenName");
        }
        await _userManager.DeleteAsync(deleteUser);
        return Ok(deleteUser);
    }

}