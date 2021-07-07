#region using

using System;

#endregion

namespace SecureAPI.Shared.DTO
{
    /// <summary>
    /// Data transfer object with user token data.
    /// </summary>
    public class UserTokenDTO
    {
        /// <summary>
        /// JSON token.
        /// </summary>
        public string Token { get; init; }

        /// <summary>
        /// Token expiration.
        /// </summary>
        public DateTime Expiration { get; init;  }

        /// <summary>
        /// Indicates if the user login was successful.
        /// </summary>
        public bool LoginSuccessful { get; init; } = false;
    }
}
