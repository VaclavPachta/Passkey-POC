using Fido2NetLib;
using Passkey_POC.api.Endpoints;
using Passkey_POC.api.Services;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

builder.Services.AddMemoryCache();
builder.Services.AddDistributedMemoryCache();
builder.Services.AddSingleton<IUserService, UserService>();


builder.Services.AddFido2(options =>
    {
        options.ServerDomain = builder.Configuration["fido2:serverDomain"];
        options.ServerName = "FIDO2 Test";
        options.Origins = builder.Configuration.GetSection("fido2:origins").Get<HashSet<string>>();
        options.TimestampDriftTolerance = builder.Configuration.GetValue<int>("fido2:timestampDriftTolerance");
        options.MDSCacheDirPath = builder.Configuration["fido2:MDSCacheDirPath"];
        options.BackupEligibleCredentialPolicy =
            builder.Configuration.GetValue<Fido2Configuration.CredentialBackupPolicy>(
                "fido2:backupEligibleCredentialPolicy");
        options.BackedUpCredentialPolicy =
            builder.Configuration.GetValue<Fido2Configuration.CredentialBackupPolicy>("fido2:backedUpCredentialPolicy");
    })
    .AddCachedMetadataService(config =>
    {
        config.AddFidoMetadataRepository(httpClientBuilder =>
        {
            //TODO: any specific config you want for accessing the MDS
        });
    });

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();


app.MapCredentialEndpoints()
    .MapAssertionsEndpoints();

app.Run();