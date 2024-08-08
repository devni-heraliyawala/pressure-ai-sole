using AI.Sole.WebAPI;
using AspNetCore.Identity.Mongo;
using Duende.IdentityServer.Stores;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using MongoDB.Driver;
using System.Text.Json.Serialization;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc;
using MongoDB.Bson.Serialization;
using System.Net.WebSockets;
using FirebaseAdmin;
using Google.Apis.Auth.OAuth2;

var builder = WebApplication.CreateBuilder(args);

string pathToFirebaseConfigJsonFile = Path.Combine(Directory.GetCurrentDirectory(), "firebaseConfig.json");

FirebaseApp.Create(new AppOptions()
{
    Credential = GoogleCredential.FromFile(pathToFirebaseConfigJsonFile)
});
// Add services to the DI container.
var services = builder.Services;
var configuration = builder.Configuration;

// Add services to the container.


AppSettingsHelper.AppSettingsConfigure(builder.Configuration);

// Configure MongoDB
var mongoClient = new MongoClient(Globals.MONGO_CONNECTION);
var database = mongoClient.GetDatabase(Globals.MONGO_DBNAME);

builder.Services.AddSingleton<IMongoDatabase>(database);

// Add ASP.NET Identity using MongoDB
builder.Services.AddIdentity<ApplicationUser, ApplicationRole>(options =>
{
    options.Password.RequireDigit = true;
    options.Password.RequireLowercase = true;
    options.Password.RequireUppercase = true;
    options.Password.RequireNonAlphanumeric = true;
    options.Password.RequiredLength = 6;
    options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(15);
    options.Lockout.MaxFailedAccessAttempts = 5;
    options.Lockout.AllowedForNewUsers = true;
    options.SignIn.RequireConfirmedAccount = true;
})
    .AddMongoDbStores<ApplicationUser, ApplicationRole, Guid>(options =>
    {
        options.ConnectionString = Globals.MONGO_CONNECTION;
    })
    .AddDefaultTokenProviders();

// Configure the rest of your IdentityServer setup
builder.Services.AddIdentityServer()
    .AddAspNetIdentity<ApplicationUser>()
    .AddInMemoryClients(IdentityConfig.GetClients())
    .AddInMemoryApiResources(IdentityConfig.GetApiResources())
    .AddInMemoryIdentityResources(IdentityConfig.GetIdentityResources())
    .AddDeveloperSigningCredential();

services.AddControllersWithViews();

var key = Convert.FromBase64String(Globals.JWT_SECRET_KEY);
var issuer = Globals.JWT_ISSUER;

// Configure authentication
services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
}).AddJwtBearer(options =>
{
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = true,
        ValidateAudience = true,
        ValidateLifetime = true,
        ValidateIssuerSigningKey = true,
        ValidIssuer = issuer,
        ValidAudience = issuer,
        IssuerSigningKey = new SymmetricSecurityKey(key)
    };
});

services.AddAuthorization(options =>
{
    options.AddPolicy("RequireAdminRole", policy => policy.RequireRole("systemAdmin"));
    options.AddPolicy("RequireDoctorRole", policy => policy.RequireRole("doctor"));
    options.AddPolicy("RequirePatientRole", policy => policy.RequireRole("patient"));
    options.AddPolicy("ApiScope", policy =>
    {
        policy.RequireAuthenticatedUser();
        policy.RequireClaim("scope", "api1");
    });
});

services.AddHttpContextAccessor();
services.AddMemoryCache();

services.AddSingleton<MongoDbContext>();
builder.Services.AddSingleton<IClientStore, ClientStore>();
services.AddTransient<IEmailService, EmailService>();


// Add Swagger for API documentation
services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new OpenApiInfo { Title = "AI Sole", Version = "v1" });

    // Add JWT Authentication
    c.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
    {
        In = ParameterLocation.Header,
        Description = "Please enter JWT with Bearer into field",
        Name = "Authorization",
        Type = SecuritySchemeType.ApiKey,
        Scheme = "Bearer"
    });
    c.AddSecurityRequirement(new OpenApiSecurityRequirement
                {
                    {
                        new OpenApiSecurityScheme
                        {
                            Reference = new OpenApiReference
                            {
                                Type = ReferenceType.SecurityScheme,
                                Id = "Bearer"
                            }
                        },
                        new string[] { }
                    }
                });
});

services.AddControllers()
    .AddJsonOptions(options =>
    {
        options.JsonSerializerOptions.Converters.Add(new JsonStringEnumConverter());
        options.JsonSerializerOptions.PropertyNamingPolicy = JsonNamingPolicy.CamelCase;
        options.JsonSerializerOptions.WriteIndented = true;
        options.JsonSerializerOptions.ReferenceHandler = ReferenceHandler.Preserve;
    })
    .AddNewtonsoftJson(options =>
    {
        options.SerializerSettings.ReferenceLoopHandling = Newtonsoft.Json.ReferenceLoopHandling.Ignore;
        options.SerializerSettings.NullValueHandling = Newtonsoft.Json.NullValueHandling.Ignore;
        options.SerializerSettings.TypeNameHandling = Newtonsoft.Json.TypeNameHandling.Auto;
    });



// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

// MongoDB class map configuration
RegisterClassMaps();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

app.UseAuthentication();
app.UseAuthorization();

app.UseIdentityServer();

app.MapControllers()
    .RequireAuthorization("ApiScope");

app.UseWebSockets();  // Enable WebSocket support
app.Use(async (context, next) =>
{
    if (context.Request.Path == "/api/data/live")
    {
        if (context.WebSockets.IsWebSocketRequest)
        {
            WebSocket webSocket = await context.WebSockets.AcceptWebSocketAsync();
            await HandleWebSocketAsync(webSocket);
        }
        else
        {
            context.Response.StatusCode = 400;
        }
    }
    else
    {
        await next();
    }
});

 async Task HandleWebSocketAsync(WebSocket webSocket)
{
    var buffer = new byte[1024 * 4];
    WebSocketReceiveResult result = await webSocket.ReceiveAsync(new ArraySegment<byte>(buffer), CancellationToken.None);

    while (!result.CloseStatus.HasValue)
    {
        // Process the received data and send it back to the client
        // For demonstration, let's just echo back the same data received
        await webSocket.SendAsync(new ArraySegment<byte>(buffer, 0, result.Count), result.MessageType, result.EndOfMessage, CancellationToken.None);

        // Continue receiving data
        result = await webSocket.ReceiveAsync(new ArraySegment<byte>(buffer), CancellationToken.None);
    }

    // Close the WebSocket connection gracefully
    await webSocket.CloseAsync(result.CloseStatus.Value, result.CloseStatusDescription, CancellationToken.None);
}


using (var scope = app.Services.CreateScope())
{
    var services1 = scope.ServiceProvider;
    var userManager = services1.GetRequiredService<UserManager<ApplicationUser>>();
    await SeedData.Initialize(services1, userManager);
}


app.Run();

void RegisterClassMaps()
{

    MongoDB.Bson.Serialization.BsonClassMap.RegisterClassMap<Doctor>(cm =>
    {
        cm.AutoMap();
       // cm.SetDiscriminator("Doctor");
     
    });
    MongoDB.Bson.Serialization.BsonClassMap.RegisterClassMap<Patient>(cm =>
    {
        cm.AutoMap();
       // cm.SetDiscriminator("Patient");
    });
}