using System.ComponentModel.DataAnnotations;

namespace JWTAuthAspNet7WepAPI.Dtos;

public class UpdatePermissionDto
{
    [Required(ErrorMessage = "UserName is required")]
    public string UserName { get; set; }
}