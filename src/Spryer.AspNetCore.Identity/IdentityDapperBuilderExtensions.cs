namespace Spryer.AspNetCore.Identity;

using System;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;

/// <summary>
/// Contains extension methods to <see cref="IdentityBuilder"/> for adding Dapper stores.
/// </summary>
public static class IdentityDapperBuilderExtensions
{
    /// <summary>
    /// Adds Dapper implementation of ASP.NET Core Identity stores.
    /// </summary>
    /// <param name="builder">The <see cref="IdentityBuilder"/> instance this method extends.</param>
    /// <param name="setupAction">The <see cref="Action{T}"/> to configure the <see cref="DapperStoreOptions"/>.</param>
    /// <returns>The <see cref="IdentityBuilder"/> instance.</returns>
    public static IdentityBuilder AddDapperStores(this IdentityBuilder builder, Action<OptionsBuilder<DapperStoreOptions>> setupAction)
    {
        var optionsBuilder = builder.Services.AddOptions<DapperStoreOptions>();
        setupAction(optionsBuilder);
        AddStores(builder, optionsBuilder);
        return builder;
    }

    private static void AddStores(IdentityBuilder identityBuilder, OptionsBuilder<DapperStoreOptions> optionsBuilder)
    {
        var services = identityBuilder.Services;
        var userType = identityBuilder.UserType;
        var roleType = identityBuilder.RoleType;

        var identityUserType = FindGenericBaseType(userType, typeof(IdentityUser<>)) ??
            throw new InvalidOperationException($"{nameof(userType)} is not an IdentityUser<>.");
        var userKeyType = identityUserType.GenericTypeArguments[0];
        if (userKeyType == typeof(string))
        {
            optionsBuilder.Configure(options =>
            {
                options.KeyRequiresDbString = true;
            });
        }

        if (roleType != null)
        {
            if (FindGenericBaseType(roleType, typeof(IdentityRole<>)) is null)
            {
                throw new InvalidOperationException($"{nameof(roleType)} is not an IdentityRole<>.");
            }

            var userStoreType = typeof(UserStore<,,>).MakeGenericType(userType, roleType, userKeyType);
            var roleStoreType = typeof(RoleStore<,>).MakeGenericType(roleType, userKeyType);

            services.TryAddScoped(typeof(IUserStore<>).MakeGenericType(userType), userStoreType);
            services.TryAddScoped(typeof(IRoleStore<>).MakeGenericType(roleType), roleStoreType);
        }
        else
        {   // No Roles
            var userStoreType = typeof(UserOnlyStore<,>).MakeGenericType(userType, userKeyType);

            services.TryAddScoped(typeof(IUserStore<>).MakeGenericType(userType), userStoreType);
        }
    }

    private static Type? FindGenericBaseType(Type currentType, Type genericBaseType)
    {
        var type = currentType;

        while (type != null)
        {
            var genericType = type.IsGenericType ? type.GetGenericTypeDefinition() : null;
            if (genericType != null && genericType == genericBaseType)
            {
                return type;
            }
            type = type.BaseType;
        }

        return null;
    }
}
