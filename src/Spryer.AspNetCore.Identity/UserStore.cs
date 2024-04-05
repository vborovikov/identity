namespace Spryer.AspNetCore.Identity;

using System;
using System.Security.Claims;
using System.Threading;
using Dapper;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;

/// <summary>
/// Represents a new instance of a persistence store for the specified user and role types.
/// </summary>
/// <typeparam name="TUser">The type representing a user.</typeparam>
/// <typeparam name="TRole">The type representing a role.</typeparam>
/// <typeparam name="TKey">The type of the primary key for users and roles.</typeparam>
public class UserStore<TUser, TRole, TKey> : UserStoreBase<TUser, TRole, TKey,
        IdentityUserClaim<TKey>, IdentityUserRole<TKey>, IdentityUserLogin<TKey>,
        IdentityUserToken<TKey>, IdentityRoleClaim<TKey>>
    where TUser : IdentityUser<TKey>
    where TRole : IdentityRole<TKey>
    where TKey : IEquatable<TKey>
{
    private readonly IIdentityStoreQueries queries;

    /// <summary>
    /// Initializes a new instance of the <see cref="UserStore{TUser, TRole, TKey}"/> class.
    /// </summary>
    /// <param name="options">The store options.</param>
    /// <param name="describer">The <see cref="IdentityErrorDescriber"/> used to describe store errors.</param>
    public UserStore(IOptions<DapperStoreOptions> options, IdentityErrorDescriber? describer = null)
        : base(options.Value, describer ?? new())
    {
        ArgumentNullException.ThrowIfNull(options.Value.StoreQueries);
        this.queries = options.Value.StoreQueries;
    }

    /// <inheritdoc/>
    public override async Task AddClaimsAsync(TUser user, IEnumerable<Claim> claims, CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(user);
        ArgumentNullException.ThrowIfNull(claims);

        await using var cnn = await OpenDbConnectionAsync(cancellationToken);
        await using var tx = await cnn.BeginTransactionAsync(cancellationToken);
        try
        {
            foreach (var claim in claims)
            {
                await cnn.ExecuteAsync(this.queries.InsertUserClaim,
                    this.KeyRequiresDbString ?
                    new
                    {
                        UserId = ConvertIdToDbString(user.Id),
                        ClaimType = claim.Type.AsVarChar(128),
                        ClaimValue = claim.Value.AsVarChar(128),
                    } :
                    new
                    {
                        UserId = user.Id,
                        ClaimType = claim.Type.AsVarChar(128),
                        ClaimValue = claim.Value.AsVarChar(128),
                    }, tx);
            }
            await tx.CommitAsync(cancellationToken);
        }
        catch (Exception x) when (x is not OperationCanceledException)
        {
            await tx.RollbackAsync(cancellationToken);
        }
    }

    /// <inheritdoc/>
    public override async Task AddLoginAsync(TUser user, UserLoginInfo login, CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(user);
        ArgumentNullException.ThrowIfNull(login);

        await using var cnn = await OpenDbConnectionAsync(cancellationToken);
        await using var tx = await cnn.BeginTransactionAsync(cancellationToken);
        try
        {
            await cnn.ExecuteAsync(this.queries.InsertUserLogin,
                this.KeyRequiresDbString ?
                new
                {
                    UserId = ConvertIdToDbString(user.Id),
                    LoginProvider = login.LoginProvider.AsVarChar(128),
                    ProviderKey = login.ProviderKey.AsVarChar(128),
                    ProviderDisplayName = login.ProviderDisplayName.AsNVarChar(128),
                } :
                new
                {
                    UserId = user.Id,
                    LoginProvider = login.LoginProvider.AsVarChar(128),
                    ProviderKey = login.ProviderKey.AsVarChar(128),
                    ProviderDisplayName = login.ProviderDisplayName.AsNVarChar(128),
                }, tx);
            await tx.CommitAsync(cancellationToken);
        }
        catch (Exception x) when (x is not OperationCanceledException)
        {
            await tx.RollbackAsync(cancellationToken);
        }
    }

    /// <inheritdoc/>
    public override async Task AddToRoleAsync(TUser user, string normalizedRoleName, CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(user);
        ArgumentNullException.ThrowIfNull(normalizedRoleName);

        await using var cnn = await OpenDbConnectionAsync(cancellationToken);
        var role =
            await cnn.QueryFirstOrDefaultAsync<TRole>(this.queries.SelectRoleByName,
                new
                {
                    NormalizedRoleName = normalizedRoleName.AsVarChar(128)
                }) ??
            throw new InvalidOperationException($"Role '{normalizedRoleName}' does not exist.");

        await using var tx = await cnn.BeginTransactionAsync(cancellationToken);
        try
        {
            await cnn.ExecuteAsync(this.queries.InsertUserRole,
                this.KeyRequiresDbString ?
                new
                {
                    UserId = ConvertIdToDbString(user.Id),
                    RoleId = ConvertIdToDbString(role.Id),
                } :
                new
                {
                    UserId = user.Id,
                    RoleId = role.Id,
                }, tx);

            await tx.CommitAsync(cancellationToken);
        }
        catch (Exception x) when (x is not OperationCanceledException)
        {
            await tx.RollbackAsync(cancellationToken);
        }
    }

    /// <inheritdoc/>
    public override async Task<IdentityResult> CreateAsync(TUser user, CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(user);

        await using var cnn = await OpenDbConnectionAsync(cancellationToken);
        await using var tx = await cnn.BeginTransactionAsync(cancellationToken);
        try
        {
            await cnn.ExecuteAsync(this.queries.InsertUser,
                this.KeyRequiresDbString ?
                new
                {
                    Id = ConvertIdToDbString(user.Id),
                    UserName = user.UserName.AsNVarChar(256),
                    NormalizedUserName = user.NormalizedUserName.AsNVarChar(256),
                    Email = user.Email.AsNVarChar(256),
                    NormalizedEmail = user.NormalizedEmail.AsVarChar(256),
                    EmailConfirmed = user.EmailConfirmed,
                    PasswordHash = user.PasswordHash.AsVarChar(128),
                    SecurityStamp = user.SecurityStamp.AsVarChar(128),
                    ConcurrencyStamp = user.ConcurrencyStamp.AsVarChar(128),
                    PhoneNumber = user.PhoneNumber.AsNVarChar(128),
                    PhoneNumberConfirmed = user.PhoneNumberConfirmed,
                    TwoFactorEnabled = user.TwoFactorEnabled,
                    LockoutEnd = user.LockoutEnd,
                    LockoutEnabled = user.LockoutEnabled,
                    AccessFailedCount = user.AccessFailedCount,
                } :
                new
                {
                    Id = user.Id,
                    UserName = user.UserName.AsNVarChar(256),
                    NormalizedUserName = user.NormalizedUserName.AsNVarChar(256),
                    Email = user.Email.AsNVarChar(256),
                    NormalizedEmail = user.NormalizedEmail.AsVarChar(256),
                    EmailConfirmed = user.EmailConfirmed,
                    PasswordHash = user.PasswordHash.AsVarChar(128),
                    SecurityStamp = user.SecurityStamp.AsVarChar(128),
                    ConcurrencyStamp = user.ConcurrencyStamp.AsVarChar(128),
                    PhoneNumber = user.PhoneNumber.AsNVarChar(128),
                    PhoneNumberConfirmed = user.PhoneNumberConfirmed,
                    TwoFactorEnabled = user.TwoFactorEnabled,
                    LockoutEnd = user.LockoutEnd,
                    LockoutEnabled = user.LockoutEnabled,
                    AccessFailedCount = user.AccessFailedCount,
                }, tx);

            await tx.CommitAsync(cancellationToken);
            return IdentityResult.Success;
        }
        catch (Exception x) when (x is not OperationCanceledException)
        {
            await tx.RollbackAsync(cancellationToken);
            return IdentityResult.Failed(this.ErrorDescriber.DefaultError());
        }
    }

    /// <inheritdoc/>
    public override async Task<IdentityResult> DeleteAsync(TUser user, CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(user);

        await using var cnn = await OpenDbConnectionAsync(cancellationToken);
        await using var tx = await cnn.BeginTransactionAsync(cancellationToken);
        try
        {
            await cnn.ExecuteAsync(this.queries.DeleteUser,
                this.KeyRequiresDbString ?
                new
                {
                    UserId = ConvertIdToDbString(user.Id)
                } :
                new
                {
                    UserId = user.Id
                }, tx);

            await tx.CommitAsync(cancellationToken);
            return IdentityResult.Success;
        }
        catch (Exception x) when (x is not OperationCanceledException)
        {
            await tx.RollbackAsync(cancellationToken);
            return IdentityResult.Failed(this.ErrorDescriber.DefaultError());
        }
    }

    /// <inheritdoc/>
    public override async Task<TUser?> FindByEmailAsync(string normalizedEmail, CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(normalizedEmail);

        await using var cnn = await OpenDbConnectionAsync(cancellationToken);
        var user = await cnn.QuerySingleOrDefaultAsync<TUser>(this.queries.SelectUserByEmail,
            new
            {
                NormalizedEmail = normalizedEmail.AsVarChar(256)
            });
        return user;
    }

    /// <inheritdoc/>
    public override Task<TUser?> FindByIdAsync(string userId, CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(userId);

        return FindUserAsync(ConvertIdFromString(userId)!, cancellationToken);
    }

    /// <inheritdoc/>
    public override async Task<TUser?> FindByNameAsync(string normalizedUserName, CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(normalizedUserName);

        await using var cnn = await OpenDbConnectionAsync(cancellationToken);
        var user = await cnn.QuerySingleOrDefaultAsync<TUser>(this.queries.SelectUserByName,
            new
            {
                NormalizedUserName = normalizedUserName.AsNVarChar(256)
            });
        return user;
    }

    /// <inheritdoc/>
    public override async Task<IList<Claim>> GetClaimsAsync(TUser user, CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(user);

        await using var cnn = await OpenDbConnectionAsync(cancellationToken);
        var userClaims = await cnn.QueryAsync<IdentityUserClaim<TKey>>(this.queries.SelectUserClaims,
            this.KeyRequiresDbString ?
            new
            {
                UserId = ConvertIdToDbString(user.Id)
            } :
            new
            {
                UserId = user.Id
            });
        return userClaims.Select(uc => uc.ToClaim()).ToArray();
    }

    /// <inheritdoc/>
    public override async Task<IList<UserLoginInfo>> GetLoginsAsync(TUser user, CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(user);

        await using var cnn = await OpenDbConnectionAsync(cancellationToken);
        var userLogins = await cnn.QueryAsync<IdentityUserLogin<TKey>>(this.queries.SelectUserLogins,
            this.KeyRequiresDbString ?
            new
            {
                UserId = ConvertIdToDbString(user.Id)
            } :
            new
            {
                UserId = user.Id
            });
        return userLogins.Select(ul => new UserLoginInfo(ul.LoginProvider, ul.ProviderKey, ul.ProviderDisplayName)).ToArray();
    }

    /// <inheritdoc/>
    public override async Task<IList<string>> GetRolesAsync(TUser user, CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(user);

        await using var cnn = await OpenDbConnectionAsync(cancellationToken);
        var userRoles = await cnn.QueryAsync<string>(this.queries.SelectUserRoles,
            this.KeyRequiresDbString ?
            new
            {
                UserId = ConvertIdToDbString(user.Id)
            } :
            new
            {
                UserId = user.Id
            });
        return userRoles.ToArray();
    }

    /// <inheritdoc/>
    public override async Task<IList<TUser>> GetUsersForClaimAsync(Claim claim, CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(claim);

        await using var cnn = await OpenDbConnectionAsync(cancellationToken);
        var users = await cnn.QueryAsync<TUser>(this.queries.SelectUsersByClaim,
            new
            {
                ClaimValue = claim.Value.AsVarChar(128),
                ClaimType = claim.Type.AsVarChar(128)
            });

        return users.ToArray();
    }

    /// <inheritdoc/>
    public override async Task<IList<TUser>> GetUsersInRoleAsync(string normalizedRoleName, CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(normalizedRoleName);

        await using var cnn = await OpenDbConnectionAsync(cancellationToken);
        var users = await cnn.QueryAsync<TUser>(this.queries.SelectUsersInRole,
            new
            {
                NormalizedRoleName = normalizedRoleName.AsVarChar(128)
            });

        return users.ToArray();
    }

    /// <inheritdoc/>
    public override async Task<bool> IsInRoleAsync(TUser user, string normalizedRoleName, CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(user);
        ArgumentNullException.ThrowIfNull(normalizedRoleName);

        await using var cnn = await OpenDbConnectionAsync(cancellationToken);
        var userRole = await cnn.QueryFirstOrDefaultAsync<IdentityUserRole<TKey>>(this.queries.SelectUserRole,
            this.KeyRequiresDbString ?
            new
            {
                UserId = ConvertIdToDbString(user.Id),
                NormalizedRoleName = normalizedRoleName.AsVarChar(128)
            } :
            new
            {
                UserId = user.Id,
                NormalizedRoleName = normalizedRoleName.AsVarChar(128)
            });
        return userRole is not null;
    }

    /// <inheritdoc/>
    public override async Task RemoveClaimsAsync(TUser user, IEnumerable<Claim> claims, CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(user);
        ArgumentNullException.ThrowIfNull(claims);

        await using var cnn = await OpenDbConnectionAsync(cancellationToken);
        await using var tx = await cnn.BeginTransactionAsync(cancellationToken);
        try
        {
            foreach (var claim in claims)
            {
                await cnn.ExecuteAsync(this.queries.DeleteUserClaim,
                    this.KeyRequiresDbString ?
                    new
                    {
                        UserId = ConvertIdToDbString(user.Id),
                        ClaimType = claim.Type.AsVarChar(128),
                        ClaimValue = claim.Value.AsVarChar(128),
                    } :
                    new
                    {
                        UserId = user.Id,
                        ClaimType = claim.Type.AsVarChar(128),
                        ClaimValue = claim.Value.AsVarChar(128),
                    }, tx);
            }

            await tx.CommitAsync(cancellationToken);
        }
        catch (Exception x) when (x is not OperationCanceledException)
        {
            await tx.RollbackAsync(cancellationToken);
        }
    }

    /// <inheritdoc/>
    public override async Task RemoveFromRoleAsync(TUser user, string normalizedRoleName, CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(user);
        ArgumentNullException.ThrowIfNull(normalizedRoleName);

        await using var cnn = await OpenDbConnectionAsync(cancellationToken);
        await using var tx = await cnn.BeginTransactionAsync(cancellationToken);
        try
        {
            await cnn.ExecuteAsync(this.queries.DeleteUserRole,
                this.KeyRequiresDbString ?
                new
                {
                    UserId = ConvertIdToDbString(user.Id),
                    NormalizedRoleName = normalizedRoleName.AsVarChar(128)
                } :
                new
                {
                    UserId = user.Id,
                    NormalizedRoleName = normalizedRoleName.AsVarChar(128)
                }, tx);
            await tx.CommitAsync(cancellationToken);
        }
        catch (Exception x) when (x is not OperationCanceledException)
        {
            await tx.RollbackAsync(cancellationToken);
        }
    }

    /// <inheritdoc/>
    public override async Task RemoveLoginAsync(TUser user, string loginProvider, string providerKey, CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(user);
        ArgumentNullException.ThrowIfNull(loginProvider);
        ArgumentNullException.ThrowIfNull(providerKey);

        await using var cnn = await OpenDbConnectionAsync(cancellationToken);
        await using var tx = await cnn.BeginTransactionAsync(cancellationToken);
        try
        {
            await cnn.ExecuteAsync(this.queries.DeleteUserLogin,
                this.KeyRequiresDbString ?
                new
                {
                    UserId = ConvertIdToDbString(user.Id),
                    LoginProvider = loginProvider.AsVarChar(128),
                    ProviderKey = providerKey.AsVarChar(128)
                } :
                new
                {
                    UserId = user.Id,
                    LoginProvider = loginProvider.AsVarChar(128),
                    ProviderKey = providerKey.AsVarChar(128)
                }, tx);
            await tx.CommitAsync(cancellationToken);
        }
        catch (Exception x) when (x is not OperationCanceledException)
        {
            await tx.RollbackAsync(cancellationToken);
        }
    }

    /// <inheritdoc/>
    public override async Task ReplaceClaimAsync(TUser user, Claim claim, Claim newClaim, CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(user);
        ArgumentNullException.ThrowIfNull(claim);
        ArgumentNullException.ThrowIfNull(newClaim);

        await using var cnn = await OpenDbConnectionAsync(cancellationToken);
        await using var tx = await cnn.BeginTransactionAsync(cancellationToken);
        try
        {
            await cnn.ExecuteAsync(this.queries.UpdateUserClaim,
                this.KeyRequiresDbString ?
                new
                {
                    UserId = ConvertIdToDbString(user.Id),
                    OldClaimType = claim.Type.AsVarChar(128),
                    OldClaimValue = claim.Value.AsVarChar(128),
                    NewClaimType = newClaim.Type.AsVarChar(128),
                    NewClaimValue = newClaim.Value.AsVarChar(128),
                } :
                new
                {
                    UserId = user.Id,
                    OldClaimType = claim.Type.AsVarChar(128),
                    OldClaimValue = claim.Value.AsVarChar(128),
                    NewClaimType = newClaim.Type.AsVarChar(128),
                    NewClaimValue = newClaim.Value.AsVarChar(128),
                }, tx);
            await tx.CommitAsync(cancellationToken);
        }
        catch (Exception x) when (x is not OperationCanceledException)
        {
            await tx.RollbackAsync(cancellationToken);
        }
    }

    /// <inheritdoc/>
    public override async Task<IdentityResult> UpdateAsync(TUser user, CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(user);

        await using var cnn = await OpenDbConnectionAsync(cancellationToken);
        await using var tx = await cnn.BeginTransactionAsync(cancellationToken);
        try
        {
            user.ConcurrencyStamp = Guid.NewGuid().ToString();

            await cnn.ExecuteAsync(this.queries.UpdateUser,
                this.KeyRequiresDbString ?
                new
                {
                    Id = ConvertIdToDbString(user.Id),
                    UserName = user.UserName.AsNVarChar(256),
                    NormalizedUserName = user.NormalizedUserName.AsNVarChar(256),
                    Email = user.Email.AsNVarChar(256),
                    NormalizedEmail = user.NormalizedEmail.AsVarChar(256),
                    EmailConfirmed = user.EmailConfirmed,
                    PasswordHash = user.PasswordHash.AsVarChar(128),
                    SecurityStamp = user.SecurityStamp.AsVarChar(128),
                    ConcurrencyStamp = user.ConcurrencyStamp.AsVarChar(128),
                    PhoneNumber = user.PhoneNumber.AsNVarChar(128),
                    PhoneNumberConfirmed = user.PhoneNumberConfirmed,
                    TwoFactorEnabled = user.TwoFactorEnabled,
                    LockoutEnd = user.LockoutEnd,
                    LockoutEnabled = user.LockoutEnabled,
                    AccessFailedCount = user.AccessFailedCount,
                } :
                new
                {
                    Id = user.Id,
                    UserName = user.UserName.AsNVarChar(256),
                    NormalizedUserName = user.NormalizedUserName.AsNVarChar(256),
                    Email = user.Email.AsNVarChar(256),
                    NormalizedEmail = user.NormalizedEmail.AsVarChar(256),
                    EmailConfirmed = user.EmailConfirmed,
                    PasswordHash = user.PasswordHash.AsVarChar(128),
                    SecurityStamp = user.SecurityStamp.AsVarChar(128),
                    ConcurrencyStamp = user.ConcurrencyStamp.AsVarChar(128),
                    PhoneNumber = user.PhoneNumber.AsNVarChar(128),
                    PhoneNumberConfirmed = user.PhoneNumberConfirmed,
                    TwoFactorEnabled = user.TwoFactorEnabled,
                    LockoutEnd = user.LockoutEnd,
                    LockoutEnabled = user.LockoutEnabled,
                    AccessFailedCount = user.AccessFailedCount,
                }, tx);

            await tx.CommitAsync(cancellationToken);
            return IdentityResult.Success;
        }
        catch (Exception x) when (x is not OperationCanceledException)
        {
            await tx.RollbackAsync(cancellationToken);
            return IdentityResult.Failed(this.ErrorDescriber.DefaultError());
        }
    }

    /// <inheritdoc/>
    protected override async Task AddUserTokenAsync(IdentityUserToken<TKey> token)
    {
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(token);

        await using var cnn = await OpenDbConnectionAsync(default);
        await using var tx = await cnn.BeginTransactionAsync(default);
        try
        {
            await cnn.ExecuteAsync(this.queries.InsertUserToken,
                this.KeyRequiresDbString ?
                new
                {
                    UserId = ConvertIdToDbString(token.UserId),
                    LoginProvider = token.LoginProvider.AsVarChar(128),
                    Name = token.Name.AsVarChar(128),
                    Value = token.Value.AsVarChar(128),
                } :
                new
                {
                    UserId = token.UserId,
                    LoginProvider = token.LoginProvider.AsVarChar(128),
                    Name = token.Name.AsVarChar(128),
                    Value = token.Value.AsVarChar(128),
                }, tx);

            await tx.CommitAsync();
        }
        catch (Exception x) when (x is not OperationCanceledException)
        {
            await tx.RollbackAsync();
        }
    }

    /// <inheritdoc/>
    protected override async Task<TRole?> FindRoleAsync(string normalizedRoleName, CancellationToken cancellationToken)
    {
        ThrowIfDisposed();
        ArgumentException.ThrowIfNullOrWhiteSpace(normalizedRoleName);

        await using var cnn = await OpenDbConnectionAsync(cancellationToken);
        var role = await cnn.QuerySingleOrDefaultAsync<TRole>(this.queries.SelectRole,
            new
            {
                NormalizedRoleName = normalizedRoleName.AsVarChar(128)
            });
        return role;
    }

    /// <inheritdoc/>
    protected override async Task<IdentityUserToken<TKey>?> FindTokenAsync(TUser user, string loginProvider, string name, CancellationToken cancellationToken)
    {
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(user);
        ArgumentNullException.ThrowIfNull(loginProvider);
        ArgumentNullException.ThrowIfNull(name);

        await using var cnn = await OpenDbConnectionAsync(cancellationToken);
        var token = await cnn.QuerySingleOrDefaultAsync<IdentityUserToken<TKey>>(this.queries.SelectUserToken,
            this.KeyRequiresDbString ?
            new
            {
                UserId = ConvertIdToDbString(user.Id),
                LoginProvider = loginProvider.AsVarChar(128),
                TokenName = name.AsVarChar(128)
            } :
            new
            {
                UserId = user.Id,
                LoginProvider = loginProvider.AsVarChar(128),
                TokenName = name.AsVarChar(128)
            });
        return token;
    }

    /// <inheritdoc/>
    protected override async Task<TUser?> FindUserAsync(TKey userId, CancellationToken cancellationToken)
    {
        ThrowIfDisposed();

        await using var cnn = await OpenDbConnectionAsync(cancellationToken);
        var user = await cnn.QuerySingleOrDefaultAsync<TUser>(this.queries.SelectUser,
            this.KeyRequiresDbString ?
            new
            {
                UserId = ConvertIdToDbString(userId)
            } :
            new
            {
                UserId = userId
            });
        return user;
    }

    /// <inheritdoc/>
    protected override async Task<IdentityUserLogin<TKey>?> FindUserLoginAsync(TKey userId, string loginProvider, string providerKey, CancellationToken cancellationToken)
    {
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(loginProvider);
        ArgumentNullException.ThrowIfNull(providerKey);

        await using var cnn = await OpenDbConnectionAsync(cancellationToken);
        var login = await cnn.QuerySingleOrDefaultAsync<IdentityUserLogin<TKey>>(this.queries.SelectUserLoginByUser,
            this.KeyRequiresDbString ?
            new
            {
                UserId = ConvertIdToDbString(userId),
                LoginProvider = loginProvider.AsVarChar(128),
                ProviderKey = providerKey.AsVarChar(128)
            } :
            new
            {
                UserId = userId,
                LoginProvider = loginProvider.AsVarChar(128),
                ProviderKey = providerKey.AsVarChar(128)
            });
        return login;
    }

    /// <inheritdoc/>
    protected override async Task<IdentityUserLogin<TKey>?> FindUserLoginAsync(string loginProvider, string providerKey, CancellationToken cancellationToken)
    {
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(loginProvider);
        ArgumentNullException.ThrowIfNull(providerKey);

        await using var cnn = await OpenDbConnectionAsync(cancellationToken);
        var login = await cnn.QuerySingleOrDefaultAsync<IdentityUserLogin<TKey>>(this.queries.SelectUserLoginByProvider,
            new
            {
                LoginProvider = loginProvider.AsVarChar(128),
                ProviderKey = providerKey.AsVarChar(128)
            });
        return login;
    }

    /// <inheritdoc/>
    protected override async Task<IdentityUserRole<TKey>?> FindUserRoleAsync(TKey userId, TKey roleId, CancellationToken cancellationToken)
    {
        ThrowIfDisposed();

        await using var cnn = await OpenDbConnectionAsync(cancellationToken);
        var userRole = await cnn.QuerySingleOrDefaultAsync<IdentityUserRole<TKey>>(this.queries.SelectUserRoleByIds,
            this.KeyRequiresDbString ?
            new
            {
                UserId = ConvertIdToDbString(userId),
                RoleId = ConvertIdToDbString(roleId)
            } :
            new
            {
                UserId = userId,
                RoleId = roleId
            });
        return userRole;
    }

    /// <inheritdoc/>
    protected override async Task RemoveUserTokenAsync(IdentityUserToken<TKey> token)
    {
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(token);

        await using var cnn = await OpenDbConnectionAsync(default);
        await using var tx = await cnn.BeginTransactionAsync(default);
        try
        {
            await cnn.ExecuteAsync(this.queries.DeleteUserToken,
                this.KeyRequiresDbString ?
                new
                {
                    UserId = ConvertIdToDbString(token.UserId),
                    LoginProvider = token.LoginProvider.AsVarChar(128),
                    Name = token.Name.AsVarChar(128),
                } :
                new
                {
                    UserId = token.UserId,
                    LoginProvider = token.LoginProvider.AsVarChar(128),
                    Name = token.Name.AsVarChar(128),
                }, tx);

            await tx.CommitAsync();
        }
        catch (Exception x) when (x is not OperationCanceledException)
        {
            await tx.RollbackAsync();
        }
    }
}
