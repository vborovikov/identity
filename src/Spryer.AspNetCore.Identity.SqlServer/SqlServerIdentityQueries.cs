namespace Spryer.AspNetCore.Identity.SqlServer;

sealed class SqlServerIdentityQueries : IIdentityQueries
{
    public string InsertUser =>
        """
        insert into asp.Users (
            [Id],UserName,NormalizedUserName,Email,NormalizedEmail,EmailConfirmed,
            PasswordHash,SecurityStamp,ConcurrencyStamp,PhoneNumber,PhoneNumberConfirmed,
            TwoFactorEnabled,LockoutEnd,LockoutEnabled,AccessFailedCount)
        values (
            @Id,@UserName,@NormalizedUserName,@Email,@NormalizedEmail,@EmailConfirmed,
            @PasswordHash,@SecurityStamp,@ConcurrencyStamp,@PhoneNumber,@PhoneNumberConfirmed,
            @TwoFactorEnabled,@LockoutEnd,@LockoutEnabled,@AccessFailedCount);
        """;

    public string DeleteUser => 
        """
        delete from asp.Users
        where Id = @UserId";
        """;

    public string SelectUserByEmail => 
        """
        select u.* 
        from asp.Users u 
        where u.NormalizedEmail = @NormalizedEmail;
        """;

    public string SelectUserByName => 
        """
        select u.* 
        from asp.Users u 
        where u.NormalizedUserName = @NormalizedUserName";
        """;

    public string SelectUserClaims => 
        """
        select uc.*
        from asp.UserClaims uc
        where uc.UserId = @UserId;
        """;

    public string SelectUserLogins => 
        """
        select ul.*
        from asp.UserLogins ul
        where ul.UserId = @UserId;
        """;

    public string SelectUserRoles => 
        """
        select r.Name 
        from asp.Roles r
        inner join asp.UserRoles ur on ur.RoleId = r.Id
        where ur.UserId = @UserId;
        """;

    public string SelectUsersByClaim => 
        """
        select u.* 
        from asp.Users u
        inner join asp.UserClaims uc on u.Id = uc.UserId
        where uc.ClaimVlaue = @ClaimValue and uc.ClaimType = @ClaimType;
        """;

    public string SelectUsersInRole => 
        """
        select u.* 
        from asp.Users u
        inner join asp.UserRoles ur on u.Id = ur.UserId
        inner join asp.Roles r on r.Id = ur.RoleId
        where r.NormalizedName = @NormalizedRoleName;
        """;

    public string SelectUserRole => 
        """
        select ur.*
        from asp.UserRoles ur
        inner join asp.Roles r on r.Id = ur.RoleId
        where ur.UserId = @UserId and r.NormalizedName = @NormalizedRoleName;
        """;

    public string DeleteUserClaims => 
        """
        delete from asp.UserClaims
        where UserId = @UserId and ClaimType = @ClaimType and ClaimValue = @ClaimValue;
        """;

    public string DeleteUserRole => 
        """
        delete from asp.UserRoles
        where UserId = @UserId and RoleId = (select r.Id from asp.Roles r where r.NormalizedName = @NormalizedRoleName);
        """;

    public string DeleteUserLogin => 
        """
        delete from asp.UserLogins
        where UserId = @UserId and LoginProvider = @LoginProvider and ProviderKey = @ProviderKey;
        """;

    public string UpdateUserClaim => 
        """
        update asp.UserClaims
        set ClaimType = @NewClaimType, ClaimValue = @NewClaimValue
        where UserId = @UserId and ClaimType = @OldClaimType and ClaimValue = @OldClaimValue;
        """;

    public string UpdateUser => 
        """
        update asp.Users
        set Email = @Email,
            NormalizedEmail = @NormalizedEmail,
            EmailConfirmed = @EmailConfirmed,
            PasswordHash = @PasswordHash,
            SecurityStamp = @SecurityStamp,
            ConcurrencyStamp = @ConcurrencyStamp,
            PhoneNumber = @PhoneNumber,
            PhoneNumberConfirmed = @PhoneNumberConfirmed,
            TwoFactorEnabled = @TwoFactorEnabled,
            LockoutEnd = @LockoutEnd,
            LockoutEnabled = @LockoutEnabled,
            AccessFailedCount = @AccessFailedCount
        where [Id] = @Id;
        """;

    public string InsertUserRole =>
        """
        insert into asp.UserRoles (UserId, RoleId)
        values (@UserId, @RoleId);
        """;

    public string InsertUserToken =>
        """
        insert into asp.UserTokens (UserId, LoginProvider, Name, [Value])
        values (@UserId, @LoginProvider, @Name, @Value);
        """;
    
    public string InsertUserClaims =>
        """
        insert into asp.UserClaims (UserId, ClaimType, ClaimValue)
        values (@UserId, @ClaimType, @ClaimValue);
        """;

    public string InsertUserLogin =>
        """
        insert into asp.UserLogins (UserId, LoginProvider, ProviderKey, ProviderDisplayName)
        values (@UserId, @LoginProvider, @ProviderKey, @ProviderDisplayName);
        """;

    public string SelectRole => 
        """
        select r.*
        from asp.Roles r 
        where r.NormalizedName = @NormalizedRoleName;
        """;

    public string SelectUserToken => 
        """
        select ut.*
        from asp.UserTokens ut 
        where ut.UserId = @UserId and ut.LoginProvider = @LoginProvider and ut.Name = @TokenName;
        """;

    public string SelectUser => 
        """
        select u.*
        from asp.Users u
        where u.Id = @UserId;
        """;

    public string SelectUserLoginByUser => 
        """
        select ul.*
        from asp.UserLogins ul
        where ul.UserId = @UserId and ul.LoginProvider = @LoginProvider and ul.ProviderKey = @ProviderKey;
        """;

    public string SelectUserLoginByProvider =>
        """
        select ul.*
        from asp.UserLogins ul 
        where ul.LoginProvider = @LoginProvider and ul.ProviderKey = @ProviderKey;
        """;

    public string SelectUserRoleByIds =>
        """
        select ur.*
        from asp.UserRoles ur 
        where ur.UserId = @UserId and ur.RoleId = @RoleId;
        """;

    public string DeleteUserToken => 
        """
        delete from asp.UserTokens
        where UserId = @UserId and LoginProvider = @LoginProvider and Name = @Name;
        """;

    public string InsertRoleClaim => 
        """
        insert into asp.RoleClaims (RoleId, ClaimType, ClaimValue)
        values (@RoleId, @ClaimType, @ClaimValue);
        """;

    public string InsertRole => 
        """
        insert into asp.Roles (Id, Name, NormalizedName, ConcurrencyStamp)
        values (@Id, @Name, @NormalizedName, @ConcurrencyStamp);
        """;

    public string DeleteRole => 
        """
        delete from asp.Roles
        where Id = @RoleId;
        """;

    public string SelectRoleById => 
        """
        select r.*
        from asp.Roles r
        where r.Id = @RoleId;
        """;

    public string SelectRoleByName => 
        """
        select r.*
        from asp.Roles r
        where r.NormalizedName = @NormalizedRoleName;
        """;

    public string SelectRoleClaims => 
        """
        select rc.*
        from asp.RoleClaims rc
        where rc.RoleId = @RoleId;
        """;

    public string DeleteRoleClaim => 
        """
        delete from asp.RoleClaims 
        where RoleId = @RoleId and ClaimType = @ClaimType and ClaimValue = @ClaimValue;
        """;

    public string UpdateRole => 
        """
        update asp.Roles
        set Name = @Name, NormalizedName = @NormalizedName, ConcurrencyStamp = @ConcurrencyStamp
        where Id = @Id;
        """;
}
