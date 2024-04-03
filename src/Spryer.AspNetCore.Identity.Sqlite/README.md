The ASP.NET Core Identity storage provider that uses SQLite.

## Usage

```csharp
builder.Services
    .AddDefaultIdentity<IdentityUser>()
    .AddDapperStores(options => 
    {
        options.UseSqlite();
    });
```