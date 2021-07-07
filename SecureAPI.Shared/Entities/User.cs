namespace SecureAPI.Shared.Entities
{
    /// <summary>
    /// This class implements a user.
    /// </summary>
    public class User
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
