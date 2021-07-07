#region using

using SecureAPI.Shared.DTO;

#endregion

namespace SecureAPI.Interfaces
{
    /// <summary>
    /// Defines authentication service functionality.
    /// </summary>
    public interface IAuthenticationService
    {
        /// <summary>
        /// Validates a user.
        /// </summary>
        /// <param name="userForAuthenticationDTO">Data transfer object with user data.</param>
        /// <returns>True if validation succeeded.</returns>
        bool ValidateUser(UserForAuthenticationDTO userForAuthenticationDTO);

        /// <summary>
        /// Creates a security token.
        /// </summary>
        /// <returns>Data transfer object with security token data.</returns>
        UserTokenDTO CreateToken();
    }
}
