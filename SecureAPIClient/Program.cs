#region using

using SecureAPI.Shared.DTO;
using System;
using System.Collections.Generic;
using System.Net.Http.Json;
using System.Threading.Tasks;

#endregion

namespace SecureAPIClient
{
    class Program
    {
        #region Main

        static async Task Main()
        {
            var userName = "TonySilva";
            var password = "abc123";

            var tokenData = await AuthenticationClient.LoginAsync(userName, password);

            if (!tokenData.LoginSuccessful)
                Console.WriteLine("Invalid login.");
            else
            {
                Console.WriteLine("Login successful.");
                Console.WriteLine();
                Console.WriteLine($"Token: {tokenData.Token}");
                Console.WriteLine();
                Console.WriteLine($"Token expiration: {tokenData.Expiration}");
                Console.WriteLine();

                if (AuthenticationClient.UseHasPermission("Perm_000_3"))
                {
                    Console.WriteLine("User has permission 'Perm_000_3'.");
                    Console.WriteLine();
                }

                if (!AuthenticationClient.UseHasPermission("Perm_XXX_Y"))
                {
                    Console.WriteLine("User does not have permission 'Perm_XXX_Y'.");
                    Console.WriteLine();
                }

                await MakeRequest();

                AuthenticationClient.Logout();
                // The following request will fail because the user is not authorised.
                await MakeRequest();
                await AuthenticationClient.LoginAsync(userName, password);
                // The following request will succeed again.
                await MakeRequest();

                AuthenticationClient.Logout();
            }
        }

        #endregion

        #region Private methods

        private static async Task MakeRequest()
        {
            // The user must be authenticated. If not, 401 (Unauthorized) will be returned.

            try
            {
                var users = await AuthenticationClient.HttpClient.GetFromJsonAsync<IEnumerable<UserDTO>>($"{AuthenticationClient.ApiUrl}users");

                foreach (var user in users)
                {
                    Console.WriteLine($"ID: {user.ID}; Name: {user.FirstName} {user.LastName}");
                    Console.WriteLine();
                }
            }
            catch (Exception e)
            {
                Console.WriteLine($"ERROR: {e.Message}");
                Console.WriteLine();
            }
        }

        #endregion
    }
}
