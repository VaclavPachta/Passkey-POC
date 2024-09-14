using System.ComponentModel.DataAnnotations;
using System.Text.Json;
using Fido2NetLib;
using Fido2NetLib.Objects;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Caching.Distributed;
using Passkey_POC.api.Services;

namespace Passkey_POC.api.Endpoints;

public static class AssertionssEndpoints
{
    public static IEndpointRouteBuilder MapAssertionsEndpoints(this IEndpointRouteBuilder endpoints)
    {
        var group = endpoints.MapGroup("/assertion");
        group.MapGet("/{companyId}/{username}", MakeAssertionOptionsForUser);
        group.MapGet("/", MakeAssertionOptions);
        group.MapPost("/", VerifyAssertion);

        return endpoints;
    }

    private static async Task<IResult> MakeAssertionOptionsForUser(
        [Required] [FromQuery] string companyId,
        [Required] [FromQuery] string username, 
        [FromServices] IFido2 fido2, 
        [FromServices] IDistributedCache cache,
        [FromServices] IUserService userService,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrEmpty(username) || string.IsNullOrEmpty(companyId))
        {
            return Results.BadRequest("Username and/or company id are required.");
        }

        var user = await userService.FindUser(companyId, username, cancellationToken);
        if (user == null)
        {
            return Results.NotFound("User not found.");
        }

        var existingKeys = user.Credentials.Select(c => c.Descriptor).ToList();
        var options = fido2.GetAssertionOptions(
            existingKeys, 
            UserVerificationRequirement.Discouraged,
            new AuthenticationExtensionsClientInputs
            {
                UserVerificationMethod = true,
                Extensions = true,
                DevicePubKey = new AuthenticationExtensionsDevicePublicKeyInputs()}
            );
        
        await cache.SetStringAsync(new string(options.Challenge.Select(b => (char)b).ToArray()), JsonSerializer.Serialize(options), cancellationToken);
        
        return Results.Ok(options);
    }

    private static async Task<IResult> MakeAssertionOptions(
        [FromServices] IFido2 fido2, 
        [FromServices] IDistributedCache cache,
        [FromServices] IUserService userService,
        CancellationToken cancellationToken)
    {
        var options = fido2.GetAssertionOptions(
            new List<PublicKeyCredentialDescriptor>(), 
            UserVerificationRequirement.Discouraged,
            new AuthenticationExtensionsClientInputs
            {
                UserVerificationMethod = true,
                Extensions = true,
                DevicePubKey = new AuthenticationExtensionsDevicePublicKeyInputs()}
            );
        
        await cache.SetStringAsync(new string(options.Challenge.Select(b => (char)b).ToArray()), JsonSerializer.Serialize(options), cancellationToken);
        
        return Results.Ok(options);
    }


    private static async Task<IResult> VerifyAssertion(
        [FromBody] AuthenticatorAssertionRawResponse clientResponse, 
        [FromServices] IFido2 fido2, 
        [FromServices] IDistributedCache cache,
        [FromServices] IUserService userService,
        CancellationToken cancellationToken)
    {
        // 1. Get the assertion options we sent the client remove them from memory so they can't be used again
        var response = JsonSerializer.Deserialize<AuthenticatorResponse>(clientResponse.Response.ClientDataJson);
        if (response is null)
        {
            return Results.BadRequest("Error: Could not deserialize client data");
        }
        
        var key = new string(response.Challenge.Select(b => (char)b).ToArray());
        var pendingOptionsString = await cache.GetStringAsync(key, cancellationToken);
        if (pendingOptionsString is null)
        {
            return Results.BadRequest("Error: Challenge not found, please get a new one via GET /{username?}/assertion-options");
        }

        var pendingOptions = JsonSerializer.Deserialize<AssertionOptions>(pendingOptionsString)!;

        await cache.RemoveAsync(key, cancellationToken);

        var user = await userService.FindUserByCredentialId(clientResponse.Id, cancellationToken);
        if (user is null)
        {
            return Results.NotFound("User not found.");
        }

        var creds = user.Credentials.First(crd => crd.Id == clientResponse.Id);

        var res = await fido2.MakeAssertionAsync(
            clientResponse,
            pendingOptions,
            creds.PublicKey,
            creds.DevicePublicKeys,
            creds.SignCount,
            async (args, ct) =>
            {
                var u = await userService.FindUserByCredentialId(args.CredentialId, ct);
                return u?.Credentials.FirstOrDefault(crd => crd.Id == clientResponse.Id)?.UserHandle == args.UserHandle;
            }, 
            cancellationToken);
        
        await userService.UpdateCredentials(user, res.CredentialId, res.SignCount, res.DevicePublicKey, cancellationToken);

        return Results.Ok();
    }

    private static string GetKey(string companyId, string username) => $"{companyId}|{username}";
    
    private static async Task<bool> CredentialIdUniqueToUserAsync(IsCredentialIdUniqueToUserParams args,
        CancellationToken cancellationToken)
    {
        return true;
    }
}