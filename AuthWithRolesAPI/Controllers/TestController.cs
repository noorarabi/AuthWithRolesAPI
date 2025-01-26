using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace AuthWithRolesAPI.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class TestController : ControllerBase
    {
        [HttpGet("user")]
        [Authorize(Roles = "User")]
        public IActionResult UserAccess()
        {
            return Ok("Hello, User!");
        }

        [HttpGet("admin")]
        [Authorize(Roles = "Admin")]
        public IActionResult AdminAccess()
        {
            return Ok("Hello, Admin!");
        }
    }
}
