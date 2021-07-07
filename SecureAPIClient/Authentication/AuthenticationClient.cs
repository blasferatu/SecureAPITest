#region using

using Microsoft.AspNetCore.Components.Authorization;
using SecureAPI.Shared.DTO;
using SecureAPI.Shared.Entities;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text.Json;
using System.Threading.Tasks;

#endregion

namespace SecureAPIClient
{
    /// <summary>
    /// Client side authentication functionality.
    /// </summary>
    public class AuthenticationClient
    {
        #region Properties

        /// <summary>
        /// API URL.
        /// </summary>
        public static string ApiUrl { get; } = "https://localhost:44300/api/";

        /// <summary>
        /// HttpClient instance.
        /// </summary>
        public static HttpClient HttpClient { get; } = new();

        public static AuthenticationState AuthenticationState { get; private set; } = null;

        public static List<string> UserPermissions { get; private set; } = new();

        #endregion

        #region Public methods

        /// <summary>
        /// Authenticates a user.
        /// </summary>
        /// <param name="userName">User name.</param>
        /// <param name="password">User password.</param>
        /// <returns>UserTokenDTO with user and token data.</returns>
        public static async Task<UserTokenDTO> LoginAsync(string userName, string password)
        {
            UserTokenDTO tokenData = new();
            var user = new UserForAuthenticationDTO { Password = password, UserName = userName };
            var httpResponse = await HttpClient.PostAsJsonAsync($"{ApiUrl}authentication/login", user);

            if (httpResponse.IsSuccessStatusCode)
            {
                tokenData = httpResponse.Content.ReadAsAsync<UserTokenDTO>().Result;
                BuildAuthenticationState(tokenData.Token);
            }

            return tokenData;
        }

        /// <summary>
        /// Logs out the user.
        /// </summary>
        public static void Logout()
        {
            HttpClient.DefaultRequestHeaders.Authorization = null;
        }

        /// <summary>
        /// Checks if the user has the given permission.
        /// </summary>
        /// <param name="permission">Permission t check.</param>
        /// <returns>True if the user has the given permission.</returns>
        public static bool UseHasPermission(string permission)
        {
            return UserPermissions.Contains(permission.ToUpper());
        }

        #endregion

        #region Private methods

        /// <summary>
        /// Builds authentication state.
        /// </summary>
        /// <param name="token">Security token.</param>
        /// <returns>Authentication state.</returns>
        private static AuthenticationState BuildAuthenticationState(string token)
        {
            HttpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("bearer", token);
            AuthenticationState = new AuthenticationState(
                new ClaimsPrincipal(
                    new ClaimsIdentity(
                        ParseClaims(token),
                        "jwt"
                        )
                    )
                );
            return AuthenticationState;
        }

        /// <summary>
        /// Parses the claims contained in the security token.
        /// </summary>
        /// <param name="token">Security token.</param>
        /// <returns>Claims contained in the security token.</returns>
        private static IEnumerable<Claim> ParseClaims(string token)
        {
            var claims = new List<Claim>();
            var tokenPayload = token.Split('.')[1];
            var payloadJsonBytes = ParseBase64WithoutPadding(tokenPayload);
            var keyValuePairs = JsonSerializer.Deserialize<Dictionary<string, object>>(payloadJsonBytes);

            keyValuePairs.TryGetValue(ClaimTypes.Role, out object roles);
            if (roles != null)
            {
                claims.AddRange(ParseClaims(ClaimTypes.Role, roles));
                keyValuePairs.Remove(ClaimTypes.Role);
            }

            keyValuePairs.TryGetValue(ClaimTypesCustom.Permission, out object permissions);
            if (permissions != null)
            {
                claims.AddRange(ParseClaims(ClaimTypesCustom.Permission, permissions));
                keyValuePairs.Remove(ClaimTypesCustom.Permission);
            }

            claims.AddRange(
                keyValuePairs.Select(kvp => new Claim(kvp.Key, kvp.Value.ToString()))
                );

            return claims;
        }

        /// <summary>
        /// Parses the claims with a given type.
        /// </summary>
        /// <param name="claimType">Type of claims to parse.</param>
        /// <param name="claimsItems">Claims items to parse.</param>
        /// <returns>Claims with the given type.</returns>
        private static IEnumerable<Claim> ParseClaims(string claimType, object claimsItems)
        {
            var claims = new List<Claim>();

            if (claimsItems.ToString().Trim().StartsWith("[")) // It's a JSON array.
            {
                var deseiralizedClaimsItems = JsonSerializer.Deserialize<string[]>(claimsItems.ToString());
                foreach (var parsedClaim in deseiralizedClaimsItems)
                {
                    claims.Add(
                               new Claim(claimType, parsedClaim)
                              );
                    if (claimType.Equals(ClaimTypesCustom.Permission))
                        UserPermissions.Add(parsedClaim.ToUpper());
                }

            }
            else
                // It's a single claim.
                claims.Add(
                    new Claim(claimType, claimsItems.ToString())
                    );

            return claims;
        }

        /// <summary>
        /// Parses the token base 64 payload string to an array of bytes.
        /// </summary>
        /// <param name="base64Payload">Token base 64 payload string.</param>
        /// <returns>Token payload as an array of bytes.</returns>
        private static byte[] ParseBase64WithoutPadding(string base64Payload)
        {
            base64Payload = (base64Payload.Length % 4) switch
            {
                2 => base64Payload += "==",
                3 => base64Payload += "=",
                _ => throw new ArgumentOutOfRangeException($"Illegal base 64 string: {base64Payload}")
            };
            return Convert.FromBase64String(base64Payload);
        }

        #endregion
    }
}
