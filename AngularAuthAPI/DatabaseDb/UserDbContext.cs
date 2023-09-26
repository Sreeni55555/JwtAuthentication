using AngularAuthAPI.Models;
using Microsoft.EntityFrameworkCore;

namespace AngularAuthAPI.DatabaseDb
{
    public class UserDbContext : DbContext
    {
        public UserDbContext(DbContextOptions<UserDbContext> options) : base(options) { }

        public DbSet<User> Users { get; set; }
    }
}
