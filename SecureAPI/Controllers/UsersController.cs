#region using

using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using SecureAPI.Shared.DTO;
using System.Collections.Generic;

#endregion

namespace SecureAPI.Controllers
{
    /// <summary>
    /// Exemplifies a controller protected by authorisation.
    /// </summary>
    [ApiController]
    [Route("api/[controller]")]
    [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
    public class UsersController : ControllerBase
    {
        /// <summary>
        /// Gets a list of users.
        /// </summary>
        /// <returns>List of users.</returns>
        [HttpGet]
        [ProducesResponseType(typeof(List<UserDTO>), StatusCodes.Status200OK)]
        public IActionResult GetUsers()
        {
            var users = new List<UserDTO>
            {
                new UserDTO { FirstName = "John", ID = 1, LastName = "Doe" },
                new UserDTO { FirstName = "Anna", ID = 2, LastName = "Doe" },
                new UserDTO { FirstName = "Peter", ID = 4, LastName = "Doe" }
            };
            return Ok(users);
        }
    }
}
