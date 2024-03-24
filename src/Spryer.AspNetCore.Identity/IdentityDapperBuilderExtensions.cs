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
    public static IdentityBuilder AddDapperStores(this IdentityBuilder builder, Action<OptionsBuilder<DapperStoreOptions>> setupAction)
    {
        AddStores(builder.Services, builder.UserType, builder.RoleType);
        var optionsBuilder = new OptionsBuilder<DapperStoreOptions>(builder.Services, null);
        setupAction(optionsBuilder);
        return builder;
    }

    private static void AddStores(IServiceCollection services, Type userType, Type? roleType)
    {
        var identityUserType = FindGenericBaseType(userType, typeof(IdentityUser<>)) ??
            throw new InvalidOperationException($"{nameof(userType)} is not an IdentityUser<>.");
        var userKeyType = identityUserType.GenericTypeArguments[0];

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
