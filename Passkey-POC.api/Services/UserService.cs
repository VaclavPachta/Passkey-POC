using System.Text.Json;
using Microsoft.Extensions.Caching.Distributed;
using Passkey_POC.api.Model;

namespace Passkey_POC.api.Services;

/// <summary>
/// User service with mocked user service - users and credentials are stored just during runtime
/// </summary>
public class UserService : IUserService
{
    private readonly IDistributedCache _cache;
    private readonly IList<User> _users;

    public UserService(IDistributedCache cache)
    {
        _cache = cache;
        var usersString = cache.GetString("users") ?? "[]";

        _users = new List<User>(JsonSerializer.Deserialize<IEnumerable<User>>(usersString)!);
    }

    public Task<User?> FindUser(string companyId, string username, CancellationToken cancellationToken = default)
    {
        return Task.FromResult(_users.FirstOrDefault(u => u.UserName == username && u.CompanyId == companyId));
    }

    public Task<User?> FindUserByCredentialId(byte[] credentialId, CancellationToken cancellationToken = default)
    {
        return Task.FromResult(_users.FirstOrDefault(u => u.Credentials.Any(crd => crd.Id == credentialId)));
    }

    public async Task<User> GetOrCreate(string companyId, string username,
        CancellationToken cancellationToken = default)
    {
        var user = await FindUser(companyId, username, cancellationToken);

        if (user != null) return user;

        user = new User() { Created = DateTime.Now, CompanyId = companyId, UserName = username };
        _users.Add(user);

        await Save(cancellationToken);
        return user;
    }

    public async Task AddCredentialToUser(User user, StoredCredential storedCredential, CancellationToken cancellationToken = default)
    {
        if (!_users.Contains(user))
        {
            _users.Add(user);
        }
        
        user.Credentials.Add(storedCredential);
        await Save(cancellationToken);
    }

    public async Task UpdateCredentials(User user, byte[] resCredentialId, uint resSignCount,
        byte[]? resDevicePublicKey,
        CancellationToken cancellationToken)
    {
        if (!_users.Contains(user))
        {
            _users.Add(user);
        }
        
        var crd = user.Credentials.FirstOrDefault(crd => crd.Id == resCredentialId);
        if (crd is null)
        {
            return;
        }
        
        crd.SignCount = resSignCount;
        if (resDevicePublicKey is not null && !crd.DevicePublicKeys.Contains(resDevicePublicKey))
        {
            crd.DevicePublicKeys.Add(resDevicePublicKey);
        }
        
        await Save(cancellationToken);

    }

    private async Task Save(CancellationToken cancellationToken = default)
    {
        await _cache.SetStringAsync("users", JsonSerializer.Serialize(_users), cancellationToken);
    }
}

public interface IUserService
{
    Task<User?> FindUser(string companyId, string username, CancellationToken cancellationToken = default);
    Task<User?> FindUserByCredentialId(byte[] credentialId, CancellationToken cancellationToken = default);
    Task<User> GetOrCreate(string companyId, string username, CancellationToken cancellationToken = default);
    Task AddCredentialToUser(User user, StoredCredential storedCredential, CancellationToken cancellationToken = default);
    Task UpdateCredentials(User user, byte[] resCredentialId, uint resSignCount, byte[]? resDevicePublicKey,
        CancellationToken cancellationToken);
}