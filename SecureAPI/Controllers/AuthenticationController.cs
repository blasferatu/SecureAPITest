#region using

using Microsoft.AspNetCore.Mvc;
using SecureAPI.Shared.DTO;
using SecureAPI.Interfaces;
using Microsoft.AspNetCore.Http;

#endregion

namespace SecureAPI.Controllers
{
    /// <summary>
    /// Authentication controller.
    /// </summary>
    [Route("api/[controller]")]
    [ApiController]
    public class AuthenticationController : ControllerBase
    {
        #region Private members

        private readonly IAuthenticationService _authenticationService;

        #endregion

        #region Constructor

        /// <summary>
        /// Creates a new AuthenticationController instance.
        /// </summary>
        /// <param name="authenticationService">IAuthenticationService instance.</param>
        public AuthenticationController(IAuthenticationService authenticationService)
        {
            _authenticationService = authenticationService;
        }

        #endregion

        #region Public methods

        /// <summary>
        /// Authenticates a user.
        /// </summary>
        /// <param name="userForAuthenticationDTO">Data transfer object with user data.</param>
        /// <returns></returns>
        [HttpPost("login")]
        [ProducesResponseType(typeof(UserTokenDTO), StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status401Unauthorized)]
        public IActionResult Login(UserForAuthenticationDTO userForAuthenticationDTO)
        {
            if (!_authenticationService.ValidateUser(userForAuthenticationDTO))
                return Unauthorized();

            return Ok(_authenticationService.CreateToken());
        }

        #endregion
    }
}
