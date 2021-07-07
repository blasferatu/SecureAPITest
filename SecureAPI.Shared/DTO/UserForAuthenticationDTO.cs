#region using

using System.ComponentModel.DataAnnotations;

#endregion

namespace SecureAPI.Shared.DTO
{
    /// <summary>
    /// Data transfer object with data for user authentication.
    /// </summary>
    public class UserForAuthenticationDTO
    {
        /// <summary>
        /// User name.
        /// </summary>
        [Required(ErrorMessage = "User name is required")]
        public string UserName { get; set; }

        /// <summary>
        /// Password.
        /// </summary>
        [Required(ErrorMessage = "Password is required")]
        public string Password { get; set; }
    }
}
