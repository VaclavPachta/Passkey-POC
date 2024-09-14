using System.ComponentModel.DataAnnotations;
using System.Text;
using System.Text.Json;
using Fido2NetLib;
using Fido2NetLib.Objects;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Caching.Distributed;
using Passkey_POC.api.Model;
using Passkey_POC.api.Services;

namespace Passkey_POC.api.Endpoints;

public static class CredentialsEndpoints
{
    public static IEndpointRouteBuilder MapCredentialEndpoints(this IEndpointRouteBuilder endpoints)
    {
        endpoints.MapGet("/credential", GetCredentialOptions);
        endpoints.MapPost("/credential", CreateCredentialRegistration);

        return endpoints;
    }

    private static async Task<IResult> GetCredentialOptions([Required] [FromQuery] string companyId,
        [Required] [FromQuery] string username, [FromServices] IFido2 fido2, [FromServices] IDistributedCache cache, [FromServices] IUserService userService,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrEmpty(username) || string.IsNullOrEmpty(companyId))
        {
            return Results.BadRequest("Username and/or company id are required.");
        }

        var user = await userService.GetOrCreate(companyId, username, cancellationToken);

        var key = GetKey(companyId, username);
        var fidoUser = new Fido2User() { Id = Encoding.UTF8.GetBytes(key), Name = key, DisplayName = username };

        var existingKeys = user!.Credentials.Select(c => c.Descriptor).ToList();
        var options = fido2.RequestNewCredential(fidoUser, existingKeys, AuthenticatorSelection.Default,
            AttestationConveyancePreference.None, new AuthenticationExtensionsClientInputs
            {
                Extensions = true, UserVerificationMethod = true, CredProps = true,
                DevicePubKey = new AuthenticationExtensionsDevicePublicKeyInputs
                    { Attestation = AttestationConveyancePreference.None.ToString() },
            });

        await cache.SetStringAsync($"{key}-pending", JsonSerializer.Serialize(options), cancellationToken);

        return Results.Ok(options);
    }


    private static async Task<IResult> CreateCredentialRegistration([Required] [FromQuery] string companyId,
        [Required] [FromQuery] string username, [FromServices] IFido2 fido2, [FromServices] IDistributedCache cache,
        [FromBody] AuthenticatorAttestationRawResponse attestationResponse, [FromServices] IUserService userService, CancellationToken cancellationToken)
    {
        var key = GetKey(companyId, username);
        var user = await userService.FindUser(companyId, username, cancellationToken);
        if (user == null)
        {
            return Results.NotFound("User not found.");
        }


        var optionsDataFromCache = await cache.GetStringAsync($"{key}-pending", cancellationToken);
        if (optionsDataFromCache == null)
        {
            return Results.BadRequest("User registration options not found.");
        }

        var pendingOptions = JsonSerializer.Deserialize<CredentialCreateOptions>(optionsDataFromCache)!;

        var credential = await fido2.MakeNewCredentialAsync(attestationResponse, pendingOptions, 
            async (args, ct) => (await userService.FindUserByCredentialId(args.CredentialId, ct)) != null, 
            cancellationToken: cancellationToken);

        if (credential.Result == null || !string.IsNullOrEmpty(credential.ErrorMessage))
        {
            return Results.BadRequest(credential.ErrorMessage);
        }

        var storedCredential = new StoredCredential
        {
            AttestationFormat = credential.Result!.AttestationFormat,
            Id = credential.Result.Id,
            PublicKey = credential.Result.PublicKey,
            UserHandle = credential.Result.User.Id,
            SignCount = credential.Result.SignCount,
            RegDate = DateTimeOffset.UtcNow,
            AaGuid = credential.Result.AaGuid,
            DevicePublicKeys = [credential.Result.DevicePublicKey],
            Transports = credential.Result.Transports,
            IsBackupEligible = credential.Result.IsBackupEligible,
            IsBackedUp = credential.Result.IsBackedUp,
            AttestationObject = credential.Result.AttestationObject,
            AttestationClientDataJson = credential.Result.AttestationClientDataJson,
        };
        
        var credentialTask= userService.AddCredentialToUser(user, storedCredential, cancellationToken);
        var cacheTask= cache.RemoveAsync($"{key}-pending", cancellationToken);

        await Task.WhenAll(credentialTask, cacheTask);
        
        return Results.Ok();
    }

    private static string GetKey(string companyId, string username) => $"{companyId}|{username}";
}