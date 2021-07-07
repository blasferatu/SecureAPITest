# SecureAPITest

Test project to demonstrate how to use authentication in a Web API application and how to access it from a client.

## Projects:

1. **SecureAPI** - Web API application;
1. **Secure.API.Interfaces** - Application interfaces;
1. **SecureAPI.Shared** - Shared functionality between client and server;
1. **SecureAPIClient** - Web API client.

### Configuration

#### 1. Web API (SecureAPI)

- ##### Controllers

  - **AuthenticationController** - Carries out authentication logic;
  - **DefaultController** - This controller is invoked when an empty route is supplied;
  - **UsersController** - Controller to exemplify the use of authorisation.
  
  Add The **Autorize** attribute to the action methods or to the whole controller in order to protect the action methods:

    ```csharp
    [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
    ```

  See example in **UsersController.cs**.

- ##### Extensions

  **ServiceExtensions** - Contains the **ConfigureJWT** extension method that configures JSON Web Token usage.

- ##### Services

  **AuthenticationService** - Contains all authentication-related Web API functionality.

- #### Startup.cs

  - Add the following call in method **ConfigureServices** to configure JSON Web Token usage:

    ```csharp
    services.ConfigureJWT(Configuration);
    services.AddScoped<IAuthenticationService, AuthenticationService>();
    ```

  - Add the following code to the **Configure** method:

     ```csharp
    app.UseAuthentication();
    app.UseAuthorization();
    ```

#### 2. Client application (SecureAPIClient)

- ##### Authentication

  **AuthenticationClient** - Contains all authentication-related Web API **client** functionality.

- #### Program.cs

  Contains test code.
