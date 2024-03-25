# Spryer.AspNetCore.Identity
ASP.NET Core Identity provider that uses Dapper.

## Usage

```csharp
builder.Services
    .AddIdentity<AppUser, AppRole>(options => options.SignIn.RequireConfirmedAccount = false)
    .AddDapperStores(options => 
    {
        options.UseSqlServer();
    })
    .AddDefaultUI()
    .AddDefaultTokenProviders();
```
