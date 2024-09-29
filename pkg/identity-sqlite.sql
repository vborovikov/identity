begin transaction;

create table AspNetRoles (
    Id text not null primary key,
    Name text not null,
    NormalizedName text not null unique,
    ConcurrencyStamp text not null
) without rowid;

create table AspNetUsers (
    Id text not null primary key,
    UserName text not null,
    NormalizedUserName text not null unique,
    Email text not null,
    NormalizedEmail text not null unique,
    EmailConfirmed integer not null,
    PasswordHash text not null,
    SecurityStamp text not null,
    ConcurrencyStamp text not null,
    PhoneNumber text null,
    PhoneNumberConfirmed integer not null,
    TwoFactorEnabled integer not null,
    LockoutEnd text null,
    LockoutEnabled integer not null,
    AccessFailedCount integer not null
) without rowid;

create table AspNetRoleClaims (
    RoleId text not null references AspNetRoles (Id) on delete cascade,
    ClaimType text null,
    ClaimValue text null,
    primary key (RoleId)
) without rowid;

create table AspNetUserClaims (
    UserId text not null references AspNetUsers (Id) on delete cascade,
    ClaimType text null,
    ClaimValue text null,
    primary key (UserId)
) without rowid;

create table AspNetUserLogins (
    LoginProvider text not null,
    ProviderKey text not null,
    ProviderDisplayName text null,
    UserId text not null references AspNetUsers (Id) on delete cascade,
    primary key (LoginProvider, ProviderKey)
) without rowid;

create unique index IXC_UserLogins on AspNetUserLogins (UserId, LoginProvider, ProviderKey);

create table AspNetUserRoles (
    UserId text not null references AspNetUsers (Id) on delete cascade,
    RoleId text not null references AspNetRoles (Id) on delete cascade,
    primary key (UserId, RoleId)
) without rowid;

create table AspNetUserTokens (
    UserId text not null references AspNetUsers (Id) on delete cascade,
    LoginProvider text not null,
    Name text not null,
    Value text null,
    primary key (UserId, LoginProvider, Name)
) without rowid;

commit;
