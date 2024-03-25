namespace Spryer.AspNetCore.Identity;

using System;
using System.Data.Common;
using System.Security.Claims;
using System.Threading;
using Dapper;
using Microsoft.AspNetCore.Identity;

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
    where TKey : IEquatable<TKey>, IParsable<TKey>
{
    private readonly IIdentityQueries queries;
    private readonly DbDataSource db;

    /// <summary>
    /// Initializes a new instance of the <see cref="UserStore{TUser, TRole, TKey}"/> class.
    /// </summary>
    /// <param name="identityQueries">The SQL queries used to access the store.</param>
    /// <param name="dbDataSource">The <see cref="DbDataSource"/> used to access the store.</param>
    /// <param name="describer">The <see cref="IdentityErrorDescriber"/> used to describe store errors.</param>
    public UserStore(IIdentityQueries identityQueries, DbDataSource dbDataSource, IdentityErrorDescriber describer) : base(describer)
    {
        this.queries = identityQueries;
        this.db = dbDataSource;
    }

    /// <inheritdoc/>
    public override async Task AddClaimsAsync(TUser user, IEnumerable<Claim> claims, CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(user);
        ArgumentNullException.ThrowIfNull(claims);

        await using var cnn = await this.db.OpenConnectionAsync(cancellationToken);
        await using var tx = await cnn.BeginTransactionAsync(cancellationToken);
        try
        {
            await cnn.ExecuteAsync(this.queries.InsertUserClaims,
                claims.Select(claim => CreateUserClaim(user, claim)), tx);
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

        await using var cnn = await this.db.OpenConnectionAsync(cancellationToken);
        await using var tx = await cnn.BeginTransactionAsync(cancellationToken);
        try
        {
            await cnn.ExecuteAsync(this.queries.InsertUserLogin, CreateUserLogin(user, login), tx);
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

        await using var cnn = await this.db.OpenConnectionAsync(cancellationToken);
        var role = 
            await cnn.QueryFirstOrDefaultAsync<TRole>(this.queries.SelectRoleByName, new { NormalizedRoleName = normalizedRoleName }) ??
            throw new InvalidOperationException($"Role '{normalizedRoleName}' does not exist.");

        await using var tx = await cnn.BeginTransactionAsync(cancellationToken);
        try
        {
            await cnn.ExecuteAsync(this.queries.InsertUserRole, CreateUserRole(user, role), tx);
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

        await using var cnn = await this.db.OpenConnectionAsync(cancellationToken);
        await using var tx = await cnn.BeginTransactionAsync(cancellationToken);
        try
        {
            await cnn.ExecuteAsync(this.queries.InsertUser, user, tx);
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

        await using var cnn = await this.db.OpenConnectionAsync(cancellationToken);
        await using var tx = await cnn.BeginTransactionAsync(cancellationToken);
        try
        {
            await cnn.ExecuteAsync(this.queries.DeleteUser, new { UserId = user.Id }, tx);
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

        await using var cnn = await this.db.OpenConnectionAsync(cancellationToken);
        var user = await cnn.QuerySingleOrDefaultAsync<TUser>(this.queries.SelectUserByEmail, new { NormalizedEmail = normalizedEmail });
        return user;
    }

    /// <inheritdoc/>
    public override Task<TUser?> FindByIdAsync(string userId, CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(userId);

        return FindUserAsync(TKey.Parse(userId, null), cancellationToken);
    }

    /// <inheritdoc/>
    public override async Task<TUser?> FindByNameAsync(string normalizedUserName, CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(normalizedUserName);

        await using var cnn = await this.db.OpenConnectionAsync(cancellationToken);
        var user = await cnn.QuerySingleOrDefaultAsync<TUser>(this.queries.SelectUserByName, new { NormalizedUserName = normalizedUserName });
        return user;
    }

    /// <inheritdoc/>
    public override async Task<IList<Claim>> GetClaimsAsync(TUser user, CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(user);

        await using var cnn = await this.db.OpenConnectionAsync(cancellationToken);
        var userClaims = await cnn.QueryAsync<IdentityUserClaim<TKey>>(this.queries.SelectUserClaims, new { UserId = user.Id });
        return userClaims.Select(uc => uc.ToClaim()).ToArray();
    }

    /// <inheritdoc/>
    public override async Task<IList<UserLoginInfo>> GetLoginsAsync(TUser user, CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(user);

        await using var cnn = await this.db.OpenConnectionAsync(cancellationToken);
        var userLogins = await cnn.QueryAsync<IdentityUserLogin<TKey>>(this.queries.SelectUserLogins, new { UserId = user.Id });
        return userLogins.Select(ul => new UserLoginInfo(ul.LoginProvider, ul.ProviderKey, ul.ProviderDisplayName)).ToArray();
    }

    /// <inheritdoc/>
    public override async Task<IList<string>> GetRolesAsync(TUser user, CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(user);

        await using var cnn = await this.db.OpenConnectionAsync(cancellationToken);
        var userRoles = await cnn.QueryAsync<string>(this.queries.SelectUserRoles, new { UserId = user.Id });
        return userRoles.ToArray();
    }

    /// <inheritdoc/>
    public override async Task<IList<TUser>> GetUsersForClaimAsync(Claim claim, CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(claim);

        await using var cnn = await this.db.OpenConnectionAsync(cancellationToken);
        var users = await cnn.QueryAsync<TUser>(this.queries.SelectUsersByClaim, new { ClaimValue = claim.Value, ClaimType = claim.Type });
        return users.ToArray();
    }

    /// <inheritdoc/>
    public override async Task<IList<TUser>> GetUsersInRoleAsync(string normalizedRoleName, CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(normalizedRoleName);

        await using var cnn = await this.db.OpenConnectionAsync(cancellationToken);
        var users = await cnn.QueryAsync<TUser>(this.queries.SelectUsersInRole, new { NormalizedRoleName = normalizedRoleName });

        return users.ToArray();
    }

    /// <inheritdoc/>
    public override async Task<bool> IsInRoleAsync(TUser user, string normalizedRoleName, CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(user);
        ArgumentNullException.ThrowIfNull(normalizedRoleName);

        await using var cnn = await this.db.OpenConnectionAsync(cancellationToken);
        var userRole = await cnn.QueryFirstOrDefaultAsync<IdentityUserRole<TKey>>(this.queries.SelectUserRole,
            new { UserId = user.Id, NormalizedRoleName = normalizedRoleName });
        return userRole is not null;
    }

    /// <inheritdoc/>
    public override async Task RemoveClaimsAsync(TUser user, IEnumerable<Claim> claims, CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(user);
        ArgumentNullException.ThrowIfNull(claims);

        await using var cnn = await this.db.OpenConnectionAsync(cancellationToken);
        await using var tx = await cnn.BeginTransactionAsync(cancellationToken);
        try
        {
            await cnn.ExecuteAsync(this.queries.DeleteUserClaims, claims.Select(claim => CreateUserClaim(user, claim)), tx);
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

        await using var cnn = await this.db.OpenConnectionAsync(cancellationToken);
        await using var tx = await cnn.BeginTransactionAsync(cancellationToken);
        try
        {
            await cnn.ExecuteAsync(this.queries.DeleteUserRole,
                new { UserId = user.Id, NormalizedRoleName = normalizedRoleName }, tx);
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

        await using var cnn = await this.db.OpenConnectionAsync(cancellationToken);
        await using var tx = await cnn.BeginTransactionAsync(cancellationToken);
        try
        {
            await cnn.ExecuteAsync(this.queries.DeleteUserLogin,
                new { UserId = user.Id, LoginProvider = loginProvider, ProviderKey = providerKey }, tx);
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

        await using var cnn = await this.db.OpenConnectionAsync(cancellationToken);
        await using var tx = await cnn.BeginTransactionAsync(cancellationToken);
        try
        {
            await cnn.ExecuteAsync(this.queries.UpdateUserClaim,
                new
                {
                    UserId = user.Id,
                    OldClaimType = claim.Type,
                    OldClaimValue = claim.Value,
                    NewClaimType = newClaim.Type,
                    NewClaimValue = newClaim.Value,
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

        await using var cnn = await this.db.OpenConnectionAsync(cancellationToken);
        await using var tx = await cnn.BeginTransactionAsync(cancellationToken);
        try
        {
            user.ConcurrencyStamp = Guid.NewGuid().ToString();
            await cnn.ExecuteAsync(this.queries.UpdateUser, user, tx);
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

        await using var cnn = await this.db.OpenConnectionAsync();
        await using var tx = await cnn.BeginTransactionAsync();
        try
        {
            await cnn.ExecuteAsync(this.queries.InsertUserToken, token, tx);
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

        await using var cnn = await this.db.OpenConnectionAsync(cancellationToken);
        var role = await cnn.QuerySingleOrDefaultAsync<TRole>(this.queries.SelectRole, new { NormalizedRoleName = normalizedRoleName });
        return role;
    }

    /// <inheritdoc/>
    protected override async Task<IdentityUserToken<TKey>?> FindTokenAsync(TUser user, string loginProvider, string name, CancellationToken cancellationToken)
    {
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(user);
        ArgumentNullException.ThrowIfNull(loginProvider);
        ArgumentNullException.ThrowIfNull(name);

        await using var cnn = await this.db.OpenConnectionAsync(cancellationToken);
        var token = await cnn.QuerySingleOrDefaultAsync<IdentityUserToken<TKey>>(this.queries.SelectUserToken,
            new { UserId = user.Id, LoginProvider = loginProvider, TokenName = name });
        return token;
    }

    /// <inheritdoc/>
    protected override async Task<TUser?> FindUserAsync(TKey userId, CancellationToken cancellationToken)
    {
        ThrowIfDisposed();

        await using var cnn = await this.db.OpenConnectionAsync(cancellationToken);
        var user = await cnn.QuerySingleOrDefaultAsync<TUser>(this.queries.SelectUser, new { UserId = userId });
        return user;
    }

    /// <inheritdoc/>
    protected override async Task<IdentityUserLogin<TKey>?> FindUserLoginAsync(TKey userId, string loginProvider, string providerKey, CancellationToken cancellationToken)
    {
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(loginProvider);
        ArgumentNullException.ThrowIfNull(providerKey);

        await using var cnn = await this.db.OpenConnectionAsync(cancellationToken);
        var login = await cnn.QuerySingleOrDefaultAsync<IdentityUserLogin<TKey>>(this.queries.SelectUserLoginByUser,
            new { UserId = userId, LoginProvider = loginProvider, ProviderKey = providerKey });
        return login;
    }

    /// <inheritdoc/>
    protected override async Task<IdentityUserLogin<TKey>?> FindUserLoginAsync(string loginProvider, string providerKey, CancellationToken cancellationToken)
    {
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(loginProvider);
        ArgumentNullException.ThrowIfNull(providerKey);

        await using var cnn = await this.db.OpenConnectionAsync(cancellationToken);
        var login = await cnn.QuerySingleOrDefaultAsync<IdentityUserLogin<TKey>>(this.queries.SelectUserLoginByProvider,
            new { LoginProvider = loginProvider, ProviderKey = providerKey });
        return login;
    }

    /// <inheritdoc/>
    protected override async Task<IdentityUserRole<TKey>?> FindUserRoleAsync(TKey userId, TKey roleId, CancellationToken cancellationToken)
    {
        ThrowIfDisposed();

        await using var cnn = await this.db.OpenConnectionAsync(cancellationToken);
        var userRole = await cnn.QuerySingleOrDefaultAsync<IdentityUserRole<TKey>>(this.queries.SelectUserRoleByIds,
            new { UserId = userId, RoleId = roleId });
        return userRole;
    }

    /// <inheritdoc/>
    protected override async Task RemoveUserTokenAsync(IdentityUserToken<TKey> token)
    {
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(token);

        await using var cnn = await this.db.OpenConnectionAsync();
        await using var tx = await cnn.BeginTransactionAsync();
        try
        {
            await cnn.ExecuteAsync(this.queries.DeleteUserToken, token, tx);
            await tx.CommitAsync();
        }
        catch (Exception x) when (x is not OperationCanceledException)
        {
            await tx.RollbackAsync();
        }
    }
}
