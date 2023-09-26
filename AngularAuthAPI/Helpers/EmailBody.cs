namespace AngularAuthAPI.Helpers
{
    public static class EmailBody
    {
        public static string EmailStringBody(string email,string emailToken)
        {
            return $@"<!DOCTYPE html>
<html lang=""en"">
<head>
  <meta charset=""UTF-8"">
  <meta name=""viewport"" content=""width=device-width, initial-scale=1.0"">
  <title>Document</title>
</head>
<body>
  <div>
    <h1>Reset Your Password</h1>
    <hr>
    <p>you are receiving this mail because you requested a password reset for demo</p>
    <p>please tap the below button to choose a new password</p>
    <a href=""http://localhost:4200/reset?email={email}&code={emailToken}"">Reset Password</a>

    <p>Kind Regards</p><br><br>
    <p>Sreeni</p>
  </div>
</body>
</html>";
        }
    }
}
