namespace WebApi.Models.Users;

using System.Text.Json.Serialization;
using WebApi.Entities;

public class AuthenticateResponse(User user, string jwtToken, string refreshToken)
{
    public int Id { get; set; } = user.Id;
    public string FirstName { get; set; } = user.FirstName;
    public string LastName { get; set; } = user.LastName;
    public string Username { get; set; } = user.Username;
    public string JwtToken { get; set; } = jwtToken;

    [JsonIgnore] // refresh token is returned in http only cookie
    public string RefreshToken { get; set; } = refreshToken;
}