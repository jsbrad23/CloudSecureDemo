using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using Microsoft.AspNetCore.RateLimiting;
using System.Threading.RateLimiting;

var builder = WebApplication.CreateBuilder(args);

// =================== CONFIGURACIÓN JWT (appsettings o variables de entorno) ===================
var jwtSection = builder.Configuration.GetSection("Jwt");
var jwtKey = Environment.GetEnvironmentVariable("JWT__Key") ?? jwtSection["Key"]!;
var jwtIssuer = Environment.GetEnvironmentVariable("JWT__Issuer") ?? jwtSection["Issuer"]!;
var jwtAudience = Environment.GetEnvironmentVariable("JWT__Audience") ?? jwtSection["Audience"]!;
var jwtExpires = int.TryParse(Environment.GetEnvironmentVariable("JWT__ExpiresMinutes"), out var expMin)
                  ? expMin : int.Parse(jwtSection["ExpiresMinutes"] ?? "60");

// =================== CORS (ajusta si usas frontend) ===================
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
        opt.PermitLimit = 30;                 // 30 req/min
        opt.Window = TimeSpan.FromMinutes(1);
        opt.QueueLimit = 0;                   // sin cola
        opt.QueueProcessingOrder = QueueProcessingOrder.OldestFirst;
    });
});

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

var app = builder.Build();

// =================== SWAGGER ===================
app.UseSwagger();
app.UseSwaggerUI();

// =================== HTTPS (Render/Azure ya fuerzan HTTPS, igual lo dejamos) ===================
app.UseHttpsRedirection();

// =================== HTTP SECURITY HEADERS (mejora puntaje en escáneres) ===================
app.Use(async (ctx, next) =>
{
    ctx.Response.Headers["X-Content-Type-Options"] = "nosniff";
    ctx.Response.Headers["X-Frame-Options"] = "DENY";
    ctx.Response.Headers["Referrer-Policy"] = "no-referrer";
    ctx.Response.Headers["Permissions-Policy"] = "geolocation=()"; // Ejemplo; ajusta según tu app
    // CSP mínima; si luego sirves frontend, ajústala
    ctx.Response.Headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none';";
    await next();
});

app.UseCors();
app.UseRateLimiter();
app.UseAuthentication();
app.UseAuthorization();

// =================== ENDPOINT RAÍZ (redirige a swagger) ===================
app.MapGet("/", () => Results.Redirect("/swagger"));

// =================== ENDPOINT PÚBLICO ===================
app.MapGet("/public", () => Results.Ok(new
{
    message = "Endpoint público OK",
    time = DateTime.UtcNow
}))
.RequireRateLimiting("fixed");

// =================== LOGIN (demo): devuelve JWT si user/clave son correctos ===================
app.MapPost("/login", (LoginDto dto) =>
{
    // DEMO: usuario/clave fijos. Cambia por tu validación real si deseas.
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

// =================== ENDPOINT PRIVADO (requiere JWT) ===================
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

// =================== DTOs ===================
record LoginDto(string Username, string Password);
