#region using

using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System;

#endregion

namespace SecureAPI.Controllers
{
    [Route("")]
    [ApiController]
    public class DefaultController : ControllerBase
    {
        /// <summary>
        /// Returns a welcome message.
        /// </summary>
        /// <returns>Welcome message.</returns>
        [HttpGet]
        [ProducesResponseType(typeof(string), StatusCodes.Status200OK)]
        public IActionResult Get()
        {
            return Ok($"Hello from SecureAPI endpoint running on {Environment.MachineName}.");
        }
    }
}
