namespace Spryer.AspNetCore.Identity.Sqlite;

sealed class SqliteIdentityQueries : IIdentityStoreQueries
{
    public string InsertUser =>
        """
        insert into AspNetUsers
        (
            Id, UserName, NormalizedUserName,
            Email, NormalizedEmail, EmailConfirmed,
            PasswordHash, SecurityStamp, ConcurrencyStamp,
            PhoneNumber, PhoneNumberConfirmed, TwoFactorEnabled,
            LockoutEnd, LockoutEnabled, AccessFailedCount
        )
        values
        (
            @Id, @UserName, @NormalizedUserName,
            @Email, @NormalizedEmail, @EmailConfirmed,
            @PasswordHash, @SecurityStamp, @ConcurrencyStamp,
            @PhoneNumber, @PhoneNumberConfirmed, @TwoFactorEnabled,
            @LockoutEnd, @LockoutEnabled, @AccessFailedCount
        );
        """;

    public string UpdateUser =>
        """
        update AspNetUsers
        set
            UserName = @UserName, NormalizedUserName = @NormalizedUserName,
            Email = @Email, NormalizedEmail = @NormalizedEmail, EmailConfirmed = @EmailConfirmed,
            PasswordHash = @PasswordHash, SecurityStamp = @SecurityStamp, ConcurrencyStamp = @ConcurrencyStamp,
            PhoneNumber = @PhoneNumber, PhoneNumberConfirmed = @PhoneNumberConfirmed, TwoFactorEnabled = @TwoFactorEnabled,
            LockoutEnd = @LockoutEnd, LockoutEnabled = @LockoutEnabled, AccessFailedCount = @AccessFailedCount
        where Id = @Id;
        """;

    public string DeleteUser =>
        """
        delete from AspNetUsers
        where Id = @UserId;
        """;

    public string SelectUser => 
        """
        select u.*
        from AspNetUsers u
        where u.Id = @UserId;
        """;

    public string SelectUserByEmail => 
        """
        select u.* 
        from AspNetUsers u 
        where u.NormalizedEmail = @NormalizedEmail;
        """;

    public string SelectUserByName => 
        """
        select u.* 
        from AspNetUsers u 
        where u.NormalizedUserName = @NormalizedUserName;
        """;

    public string SelectUsersByClaim => 
        """
        select u.* 
        from AspNetUsers u
        inner join AspNetUserClaims uc on u.Id = uc.UserId
        where uc.ClaimVlaue = @ClaimValue and uc.ClaimType = @ClaimType;
        """;

    public string SelectUsersInRole => 
        """
        select u.* 
        from AspNetUsers u
        inner join AspNetUserRoles ur on u.Id = ur.UserId
        inner join AspNetRoles r on r.Id = ur.RoleId
        where r.NormalizedName = @NormalizedRoleName;
        """;

    public string InsertUserClaim =>
        """
        insert into AspNetUserClaims (UserId, ClaimType, ClaimValue)
        values (@UserId, @ClaimType, @ClaimValue);
        """;

    public string UpdateUserClaim => 
        """
        update AspNetUserClaims
        set ClaimType = @NewClaimType, ClaimValue = @NewClaimValue
        where UserId = @UserId and ClaimType = @OldClaimType and ClaimValue = @OldClaimValue;
        """;

    public string DeleteUserClaim => 
        """
        delete from AspNetUserClaims
        where UserId = @UserId and ClaimType = @ClaimType and ClaimValue = @ClaimValue;
        """;

    public string SelectUserClaims => 
        """
        select uc.*
        from AspNetUserClaims uc
        where uc.UserId = @UserId;
        """;

    public string InsertUserLogin =>
        """
        insert into AspNetUserLogins (UserId, LoginProvider, ProviderKey, ProviderDisplayName)
        values (@UserId, @LoginProvider, @ProviderKey, @ProviderDisplayName);
        """;

    public string DeleteUserLogin => 
        """
        delete from AspNetUserLogins
        where UserId = @UserId and LoginProvider = @LoginProvider and ProviderKey = @ProviderKey;
        """;

    public string SelectUserLogins => 
        """
        select ul.*
        from AspNetUserLogins ul
        where ul.UserId = @UserId;
        """;

    public string SelectUserLoginByUser => 
        """
        select ul.*
        from AspNetUserLogins ul
        where ul.UserId = @UserId and ul.LoginProvider = @LoginProvider and ul.ProviderKey = @ProviderKey;
        """;

    public string SelectUserLoginByProvider =>
        """
        select ul.*
        from AspNetUserLogins ul 
        where ul.LoginProvider = @LoginProvider and ul.ProviderKey = @ProviderKey;
        """;

    public string InsertUserToken =>
        """
        insert into AspNetUserTokens (UserId, LoginProvider, Name, [Value])
        values (@UserId, @LoginProvider, @Name, @Value);
        """;
    
    public string DeleteUserToken => 
        """
        delete from AspNetUserTokens
        where UserId = @UserId and LoginProvider = @LoginProvider and Name = @Name;
        """;

    public string SelectUserToken => 
        """
        select ut.*
        from AspNetUserTokens ut 
        where ut.UserId = @UserId and ut.LoginProvider = @LoginProvider and ut.Name = @TokenName;
        """;

    public string InsertRole => 
        """
        insert into AspNetRoles (Id, Name, NormalizedName, ConcurrencyStamp)
        values (@Id, @Name, @NormalizedName, @ConcurrencyStamp);
        """;

    public string UpdateRole => 
        """
        update AspNetRoles
        set Name = @Name, NormalizedName = @NormalizedName, ConcurrencyStamp = @ConcurrencyStamp
        where Id = @Id;
        """;

    public string DeleteRole => 
        """
        delete from AspNetRoles
        where Id = @RoleId;
        """;

    public string SelectRole => 
        """
        select r.*
        from AspNetRoles r
        where r.Id = @RoleId;
        """;

    public string SelectRoleByName => 
        """
        select r.*
        from AspNetRoles r
        where r.NormalizedName = @NormalizedRoleName;
        """;

    public string InsertRoleClaim => 
        """
        insert into AspNetRoleClaims (RoleId, ClaimType, ClaimValue)
        values (@RoleId, @ClaimType, @ClaimValue);
        """;

    public string DeleteRoleClaim => 
        """
        delete from AspNetRoleClaims 
        where RoleId = @RoleId and ClaimType = @ClaimType and ClaimValue = @ClaimValue;
        """;

    public string SelectRoleClaims => 
        """
        select rc.*
        from AspNetRoleClaims rc
        where rc.RoleId = @RoleId;
        """;

    public string InsertUserRole =>
        """
        insert into AspNetUserRoles (UserId, RoleId)
        values (@UserId, @RoleId);
        """;

    public string DeleteUserRole => 
        """
        delete from AspNetUserRoles
        where UserId = @UserId and RoleId = (select r.Id from AspNetRoles r where r.NormalizedName = @NormalizedRoleName);
        """;

    public string SelectUserRole => 
        """
        select ur.*
        from AspNetUserRoles ur
        inner join AspNetRoles r on r.Id = ur.RoleId
        where ur.UserId = @UserId and r.NormalizedName = @NormalizedRoleName;
        """;

    public string SelectUserRoles => 
        """
        select r.Name 
        from AspNetRoles r
        inner join AspNetUserRoles ur on ur.RoleId = r.Id
        where ur.UserId = @UserId;
        """;

    public string SelectUserRoleByIds =>
        """
        select ur.*
        from AspNetUserRoles ur 
        where ur.UserId = @UserId and ur.RoleId = @RoleId;
        """;
}
