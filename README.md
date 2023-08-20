# Authentication Project 

## Description

This project was build in Udemy course [Master ASP.NET Core Identity: Authentication & Authorization](https://www.udemy.com/course/complete-guide-to-aspnet-core-identity/).
This project is an easy and first approach to Authentication and authorization in .Net using cookies approach

## Stack
- .Net 6
- Razor pages
- Bootstrap

## Important features

### Configuration

In Program.cs This configuration was added
- .AddAuthentication() adds the authentication configuration, the string inside is used to specify the authentication scheme
- .AddCookie() Configures the creation of the cookie in this case 'MyCookieAuthJulian' sets the authentication scheme
    - Cookie.Name Sets cookie name
    - loginPath Configures the login path so when login is needed redirects to Login page
    - AccessDeniedPath Redirects when authorization is not granted and redirects to access denied page
    - ExpireTimeSpan sets the expiration time of the cookie
```c#
builder.Services.AddAuthentication("MyCookieAuthJulian").AddCookie("MyCookieAuthJulian", options =>
{
    options.Cookie.Name = "MyCookieAuthJulian";
    options.LoginPath = "/Account/Login";
    options.AccessDeniedPath = "/Account/AccessDenied";
    options.ExpireTimeSpan = TimeSpan.FromDays(1);
});
```

In order to add some authorization policies this configuration was added, note that this is useful when adding to controller or pages using: [Autorize(Policy = "BelongHumanResources")]
- AddAuthorization() Adds authorization configuration
    - AddPolicy creates a new policy
        - policy.RequireClaim() makes the policy requieres a claim like Department with value Hr
        - .Requirements.Add() Adds a new requirement configuration, note that is also required to add configuration in Program.cs as a singleton like seen bellow, please refer to next section for Requirements configuration

```c#
builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("BelongHumanResources", policy =>
    {
        policy.RequireClaim("Department", "HR")
        .Requirements.Add(new HRManagerProbationRequirements(3));
    });

    options.AddPolicy("AdminOnly", policy =>
    {
        policy.RequireClaim("Admin")
        .Requirements.Add(new HRManagerProbationRequirements(3));
    });

    options.AddPolicy("DevelopersOnly", policy =>
    {
        policy.RequireClaim("Developer");
    });
});

builder.Services.AddSingleton<IAuthorizationHandler, HRManagerProbationRequirementsHandler>();

```

Configure Requirements configuration to configure requirements, this needs a class to inherit from 'IAuthorizationRequirement' and a handler AuthorizationHandler<>, see code bellow

```c#
using Microsoft.AspNetCore.Authorization;

namespace WebApp_.Net6.Authorization
{
    public class HRManagerProbationRequirements: IAuthorizationRequirement
    {
        public int ProbationMonths { get; }
        public HRManagerProbationRequirements(int probationMonths)
        {
            ProbationMonths = probationMonths;
        }
    }

    public class HRManagerProbationRequirementsHandler : AuthorizationHandler<HRManagerProbationRequirements>
    {
        protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, HRManagerProbationRequirements requirement)
        {
            if(!context.User.HasClaim(x => x.Type == "EmploymentDate"))
                return Task.CompletedTask;

            var empDate = DateTime.Parse(context.User.FindFirst(x => x.Type == "EmploymentDate").Value);

            var period = DateTime.Now - empDate;

            if (period.Days > 30 * requirement.ProbationMonths)
                context.Succeed(requirement);

            return Task.CompletedTask;
        }
    }
}


```

### Project structure

This project has bellow structure 
- Authorization Folder: Configures authorization requirements
- Pages
    - Account: configures Login and Logout logic and views
    - Shared: has usual shared files but also _LoginStatusPartial to handle navbar when logged ot not   
    - Developers page using Policy [Authorize(Policy = "DevelopersOnly")]
    - HumanResources using policy [Authorize(Policy = "BelongHumanResources")]
    - Settings page using [Authorize(Policy = "AdminOnly")]

### Login Configuration
Is configured in pages/Login

When the login form is posted is received by OnPostAsync(), note:
- new List<Claim>() Creates the claim list  including some customed
- new ClaimsIdentity(claims, "MyCookieAuthJulian"); initiates an a claims identity instance using claims list and authentication scheme
- new ClaimsPrincipal() Initiates an instance of claim principal and adds its identity
- new AuthenticationProperties creates new authentication properties, as in this case makes the cookies persistant so won't be deleted when browser session is finished (browser closed)

```c#
 public async Task<IActionResult> OnPostAsync()
{
    if (!ModelState.IsValid) return Page();

    //1 verify credential
    if(Credentials.UserName == "jugalo1713" && Credentials.Password == "123")
    {

        //create security context
        var claims = new List<Claim>
        {
            new Claim(ClaimTypes.Name, "jugalo1713"),
            new Claim(ClaimTypes.Email, "julianlondono@outlook.com"),
            new Claim("Department", "HR"),
            new Claim("Admin", "true"),
            new Claim("Developer", "true"),
            new Claim("EmploymentDate", "2021-08-16"),
        };

        var identity = new ClaimsIdentity(claims, "MyCookieAuthJulian");
        var principal = new ClaimsPrincipal(identity);
        var authenticationProperties = new AuthenticationProperties
        {
            IsPersistent = Credentials.RememberMe
        };

        await HttpContext.SignInAsync("MyCookieAuthJulian", principal, authenticationProperties);

        return RedirectToPage("/Index");
    }

    return Page();
}
///// Helper class creaded 

 public class Credential
{
    [Required]
    [Display(Name ="User Name")]
    public string UserName { get; set; }
    [Required]
    [DataType(DataType.Password)]
    public string Password { get; set; }

    [Display(Name = "Remember me")]
    public bool RememberMe { get; set; }

}

```

### Logout configuration

the view is not really used, when a form to logout is clicked then redirects to this page which signs out using SignOutAsync("MyCookieAuthJulian"); and an then redirects to home