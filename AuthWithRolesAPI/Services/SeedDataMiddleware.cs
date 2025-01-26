using Microsoft.AspNetCore.Identity;

namespace AuthWithRolesAPI.Services
{
    public class SeedDataMiddleware
    {
        private readonly RequestDelegate _next;

        public SeedDataMiddleware(RequestDelegate next)
        {
            _next = next;
        }

        public async Task InvokeAsync(HttpContext context, RoleManager<IdentityRole> roleManager, UserManager<IdentityUser> userManager)
        {
            await SeedRolesAndAdminUserAsync(roleManager, userManager);
            await _next(context);
        }

        private static async Task SeedRolesAndAdminUserAsync(RoleManager<IdentityRole> roleManager, UserManager<IdentityUser> userManager)
        {
            // اسم الدور الذي نريد إضافته
            var roleName = "Admin";

            // تحقق إذا كان الدور موجودًا
            if (!await roleManager.RoleExistsAsync(roleName))
            {
                var role = new IdentityRole(roleName);
                await roleManager.CreateAsync(role);
            }

            // إعدادات المستخدم Admin
            var adminUserName = "AdminUser";
            var adminEmail = "admin@yourapi.com";
            var adminPassword = "Admin@1234";

            // تحقق إذا كان المستخدم موجودًا
            var adminUser = await userManager.FindByNameAsync(adminUserName);
            if (adminUser == null)
            {
                adminUser = new IdentityUser
                {
                    UserName = adminUserName,
                    Email = adminEmail,
                    EmailConfirmed = true
                };

                var result = await userManager.CreateAsync(adminUser, adminPassword);
                if (result.Succeeded)
                {
                    await userManager.AddToRoleAsync(adminUser, roleName);
                }
            }
        }
    }

}
