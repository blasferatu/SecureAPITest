namespace SecureAPI.Shared.DTO
{
    /// <summary>
    /// Data transfer object with user data.
    /// </summary>
    public class UserDTO
    {
        /// <summary>
        /// User ID.
        /// </summary>
        public int ID { get; set; }

        /// <summary>
        /// First name.
        /// </summary>
        public string FirstName { get; set; }

        /// <summary>
        /// Last name.
        /// </summary>
        public string LastName { get; set; }
    }
}
