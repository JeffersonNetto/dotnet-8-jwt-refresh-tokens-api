﻿using Microsoft.AspNetCore.Mvc;
using WebApi.Authorization;
using WebApi.Models.Users;
using WebApi.Services;

namespace WebApi.Controllers;

[Authorize]
[ApiController]
[Route("[controller]")]
public class UsersController(IUserService userService) : ControllerBase
{
    [AllowAnonymous]
    [HttpPost("authenticate")]
    public IActionResult Authenticate(AuthenticateRequest model)
    {
        var response = userService.Authenticate(model, IpAddress());
        SetTokenCookie(response.RefreshToken);
        return Ok(response);
    }

    [AllowAnonymous]
    [HttpPost("refresh-token")]
    public IActionResult RefreshToken()
    {
        var refreshToken = Request.Cookies["refreshToken"];
        var response = userService.RefreshToken(refreshToken, IpAddress());
        SetTokenCookie(response.RefreshToken);
        return Ok(response);
    }

    [HttpPost("revoke-token")]
    public IActionResult RevokeToken(RevokeTokenRequest model)
    {
        // accept refresh token in request body or cookie
        var token = model.Token ?? Request.Cookies["refreshToken"];

        if (string.IsNullOrEmpty(token))
            return BadRequest(new { message = "Token is required" });

        userService.RevokeToken(token, IpAddress());
        return Ok(new { message = "Token revoked" });
    }

    [HttpGet]
    public IActionResult GetAll()
    {
        var users = userService.GetAll();
        return Ok(users);
    }

    [HttpGet("{id}")]
    public IActionResult GetById(int id)
    {
        var user = userService.GetById(id);
        return Ok(user);
    }

    [HttpGet("{id}/refresh-tokens")]
    public IActionResult GetRefreshTokens(int id)
    {
        var user = userService.GetById(id);
        return Ok(user.RefreshTokens);
    }

    // helper methods

    private void SetTokenCookie(string token)
    {
        // append cookie with refresh token to the http response
        var cookieOptions = new CookieOptions
        {
            HttpOnly = true,
            Expires = DateTime.UtcNow.AddDays(7)
        };
        Response.Cookies.Append("refreshToken", token, cookieOptions);
    }

    private string IpAddress()
    {
        // get source ip address for the current request
        return Request.Headers.TryGetValue("X-Forwarded-For", out Microsoft.Extensions.Primitives.StringValues value) ? 
            (string)value : 
            HttpContext.Connection.RemoteIpAddress.MapToIPv4().ToString();
    }
}