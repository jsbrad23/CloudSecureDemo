using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using System.Threading.RateLimiting;

var builder = WebApplication.CreateBuilder(args);

// =================== CONFIGURACIÓN JWT (appsettings o variables de entorno) ===================
var jwtSection = builder.Configuration.GetSection("Jwt");
var jwtKey = Environment.GetEnvironmentVariable("JWT__Key") ?? jwtSection["Key"]!;
var jwtIssuer = Environment.GetEnvironmentVariable("JWT__Issuer") ?? jwtSection["Issuer"]!;
var jwtAudience = Environment.GetEnvironmentVariable("JWT__Audience") ?? jwtSection["Audience"]!;
var jwtExpires = int.TryParse(Environment.GetEnvironmentVariable("JWT__ExpiresMinutes"), out var expMin)
                  ? expMin : int.Parse(jwtSection["ExpiresMinutes"] ?? "60");

// =================== CORS (ajusta con tu frontend si lo usas) ===================
builder.Services.AddCors(o => o.AddDefaultPolicy(p =>
    p.AllowAnyOrigin().AllowAnyHeader().AllowAnyMethod()
));

// =================== AUTENTICACIÓN JWT ===================
var signingKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtKey));

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = signingKey,
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidIssuer = jwtIssuer,
            ValidAudience = jwtAudience,
            ClockSkew = TimeSpan.Zero
        };
    });

builder.Services.AddAuthorization();

// =================== RATE LIMITING (para demostrar protección de abuso) ===================
builder.Services.AddRateLimiter(options =>
{
    options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;

    options.AddFixedWindowLimiter("fixed", opt =>
    {
        opt.PermitLimit = 30; // 30 req/min
        opt.Window = TimeSpan.FromMinutes(1);
        opt.QueueLimit = 0;
        opt.QueueProcessingOrder = QueueProcessingOrder.OldestFirst;
    });
});

builder.Services.AddEndpointsApiExplorer();

// =================== SWAGGER + ESQUEMA DE SEGURIDAD (Botón Authorize) ===================
builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new OpenApiInfo { Title = "CloudSecureDemo", Version = "v1" });

    // Definir esquema Bearer para JWT
    c.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
    {
        Name = "Authorization",
        Type = SecuritySchemeType.ApiKey,
        Scheme = "Bearer",
        BearerFormat = "JWT",
        In = ParameterLocation.Header,
        Description = "Introduce **Bearer** + espacio + tu token JWT.\n\nEjemplo: `Bearer eyJhbGciOi...`"
    });

    // Requerir el esquema en las operaciones
    c.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        {
            new OpenApiSecurityScheme
            {
                Reference = new OpenApiReference
                {
                    Type = ReferenceType.SecurityScheme,
                    Id   = "Bearer"
                }
            },
            Array.Empty<string>()
        }
    });
});

var app = builder.Build();

// =================== MIDDLEWARES ===================
app.UseSwagger();
app.UseSwaggerUI();

app.UseHttpsRedirection();

// HTTP Security Headers (mejora puntaje en escáneres)
app.Use(async (ctx, next) =>
{
    ctx.Response.Headers["X-Content-Type-Options"] = "nosniff";
    ctx.Response.Headers["X-Frame-Options"] = "DENY";
    ctx.Response.Headers["Referrer-Policy"] = "no-referrer";
    ctx.Response.Headers["Permissions-Policy"] = "geolocation=()";
    // CSP mínima; si luego sirves frontend, ajústala
    ctx.Response.Headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none';";
    await next();
});

app.UseCors();
app.UseRateLimiter();
app.UseAuthentication();
app.UseAuthorization();

// =================== ENDPOINTS ===================

// Raíz → redirige a Swagger
app.MapGet("/", () => Results.Redirect("/swagger"));

// Público
app.MapGet("/public", () => Results.Ok(new
{
    message = "Endpoint público OK",
    time = DateTime.UtcNow
}))
.RequireRateLimiting("fixed");

// Login (demo: usuario/clave fijos)
app.MapPost("/login", (LoginDto dto) =>
{
    if (dto.Username != "demo" || dto.Password != "Password123!")
        return Results.Unauthorized();

    var claims = new[]
    {
        new Claim(JwtRegisteredClaimNames.Sub, dto.Username),
        new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
        new Claim(ClaimTypes.Role, "User")
    };

    var creds = new SigningCredentials(signingKey, SecurityAlgorithms.HmacSha256);

    var token = new JwtSecurityToken(
        issuer: jwtIssuer,
        audience: jwtAudience,
        claims: claims,
        expires: DateTime.UtcNow.AddMinutes(jwtExpires),
        signingCredentials: creds
    );

    var tokenString = new JwtSecurityTokenHandler().WriteToken(token);

    return Results.Ok(new
    {
        access_token = tokenString,
        token_type = "Bearer",
        expires_in = jwtExpires * 60
    });
});

// Privado (requiere JWT)
app.MapGet("/private", (ClaimsPrincipal user) =>
{
    var name = user.Identity?.Name
               ?? user.FindFirstValue(ClaimTypes.NameIdentifier)
               ?? "anon";

    return Results.Ok(new
    {
        message = $"Hola {name}, accediste al endpoint privado.",
        time = DateTime.UtcNow
    });
})
.RequireAuthorization();

app.Run();

// DTOs
record LoginDto(string Username, string Password);
