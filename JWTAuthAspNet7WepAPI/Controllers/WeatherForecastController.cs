using JWTAuthAspNet7WepAPI.Core.OtherObjects;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace JWTAuthAspNet7WepAPI.Controllers;

[ApiController]
[Route("[controller]")]
public class WeatherForecastController : ControllerBase
{
    private static readonly string[] Summaries = new[]
    {
        "Freezing", "Bracing", "Chilly", "Cool", "Mild", "Warm", "Balmy", "Hot", "Sweltering", "Scorching"
    };

    [HttpGet]
    [Route("Get")]
    public IActionResult Get()
    {
        return Ok(Summaries);
    }
 
    [HttpGet]
    [Route("GetAppUserRole")]
    [Authorize(Roles = StaticUserRoles.APP_USER)]
    public IActionResult GetAppUserRole()
    {
        return Ok(Summaries);
    }
    
    [HttpGet]
    [Route("GetDashUserRole")]
    [Authorize(Roles = StaticUserRoles.Dash_USER)]
    public IActionResult GetDashUserRole()
    {
        return Ok(Summaries);
    }

    [HttpGet]
    [Route("GetAdminRole")]
    [Authorize(Roles = StaticUserRoles.ADMIN)]
    public IActionResult GetAdminRole()
    {
        return Ok(Summaries);
    }
    
        
    [HttpGet]
    [Route("GetSuperAdminRole")]
    [Authorize(Roles = StaticUserRoles.SUPER_ADMIN)]
    public IActionResult GetOwnerRole()
    {
        return Ok(Summaries);
    }
}