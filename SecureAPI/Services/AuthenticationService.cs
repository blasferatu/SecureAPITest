#region using

using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using SecureAPI.Shared.DTO;
using SecureAPI.Shared.Entities;
using SecureAPI.Interfaces;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

#endregion

namespace SecureAPI.Services
{
    /// <summary>
    /// Implements server side authentication service functionality.
    /// </summary>
    public class AuthenticationService : IAuthenticationService
    {
        #region Private members

        private readonly IConfiguration _configuration;

        private User _user;

        private const string CONFIG_JWT_SETTINGS_KEY = "JwtSettings";

        #endregion

        #region Constructor

        /// <summary>
        /// Creates a new AuthenticationManager instance.
        /// </summary>
        /// <param name="configuration">IConfiguration instance.</param>
        public AuthenticationService(IConfiguration configuration)
        {
            _configuration = configuration;
        }

        #endregion

        #region Public methods

        /// <summary>
        /// Creates a JWT token.
        /// </summary>
        /// <returns>UserTokenDTO object with user and token data.</returns>
        public UserTokenDTO CreateToken()
        {
            var signingCredentials = GetSigningCredentials();
            var claims = GetClaims();
            var tokenExpiration = GetTokenExpiration();
            var tokenOptions = GenerateToken(signingCredentials, claims, tokenExpiration);

            return new UserTokenDTO
            {
                Expiration = tokenExpiration,
                LoginSuccessful = true,
                Token = new JwtSecurityTokenHandler().WriteToken(tokenOptions)
            };
        }

        /// <summary>
        /// Validates a user.
        /// </summary>
        /// <param name="userForAuthenticationDTO">Data transfer object with user data.</param>
        /// <returns>True if the user has been successfully validated.</returns>
        public bool ValidateUser(UserForAuthenticationDTO userForAuthenticationDTO)
        {
            /*
              In a real scenario, the user would be validated against a database, e.g.:
             
              _user = await _userManager.FindByNameAsync(userForAuthenticationDTO.UserName);
              return (_user != null && await _userManager.CheckPasswordAsync(_user, userForAuthenticationDTO.Password));
            */
            _user = new User { ID = 1, FirstName = "Tony", LastName = "Silva" };
            return (
                !(userForAuthenticationDTO is null) &&
                userForAuthenticationDTO.UserName.ToLower().Equals("tonysilva") &&
                userForAuthenticationDTO.Password.Equals("abc123")
                );
        }

        #endregion

        #region Private methods

        /// <summary>
        /// Gets the signing credentials.
        /// </summary>
        /// <returns>Signing credentials.</returns>
        private SigningCredentials GetSigningCredentials()
        {
            var jwtSettings = _configuration.GetSection(CONFIG_JWT_SETTINGS_KEY);
            var secretKey = Encoding.UTF8.GetBytes(jwtSettings.GetSection("secretKey").Value);
            var secret = new SymmetricSecurityKey(secretKey);

            return new SigningCredentials(secret, SecurityAlgorithms.HmacSha256);
        }

        /// <summary>
        /// Gets user claims.
        /// </summary>
        /// <returns>User claims.</returns>
        private List<Claim> GetClaims()
        {
            return new List<Claim>
            {
                new Claim(ClaimTypes.Name, $"{_user.FirstName} {_user.LastName}"),
                // In a real application, permissions would be retrieved from a database, obviously.
                new Claim(ClaimTypesCustom.Permission, "PERM_000_1"),
                new Claim(ClaimTypesCustom.Permission, "PERM_000_2"),
                new Claim(ClaimTypesCustom.Permission, "PERM_000_3"),
                new Claim(ClaimTypesCustom.Permission, "PERM_000_4"),
                new Claim(ClaimTypesCustom.Permission, "PERM_000_5"),
            };
        }

        /// <summary>
        /// Gets token expiration.
        /// </summary>
        /// <returns>Token expiration.</returns>
        private DateTime GetTokenExpiration()
        {
            var jwtSettings = _configuration.GetSection(CONFIG_JWT_SETTINGS_KEY);
            return DateTime.UtcNow.AddMinutes(
                    Convert.ToDouble(jwtSettings.GetSection("expiresInMinutes").Value)
                    );
        }

        /// <summary>
        /// Generates a JWT security token.
        /// </summary>
        /// <param name="signingCredentials">Signing credentials.</param>
        /// <param name="claims">Claims.</param>
        /// <param name="tokenExpiration">Token expiration.</param>
        /// <returns></returns>
        private JwtSecurityToken GenerateToken(SigningCredentials signingCredentials, List<Claim> claims, DateTime tokenExpiration)
        {
            var jwtSettings = _configuration.GetSection(CONFIG_JWT_SETTINGS_KEY);

            return new JwtSecurityToken
                (
                issuer: jwtSettings.GetSection("validIssuer").Value,
                audience: jwtSettings.GetSection("validAudience").Value,
                claims: claims,
                expires: tokenExpiration,
                signingCredentials: signingCredentials
                );
        }

        #endregion
    }
}
