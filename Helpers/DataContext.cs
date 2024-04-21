using Microsoft.EntityFrameworkCore;
using WebApi.Entities;

namespace WebApi.Helpers;

public class DataContext : DbContext
{
    public DbSet<User> Users { get; set; }        

    protected override void OnConfiguring(DbContextOptionsBuilder options)
    {
        // in memory database used for simplicity, change to a real db for production applications
        options.UseInMemoryDatabase("TestDb");
    }
}