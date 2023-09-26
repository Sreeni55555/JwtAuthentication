namespace AngularAuthAPI.Models
{
    public class EmailModel
    {
        public string To { get;set; }
        public string Subject { get;set; }
        public string Content { get;set; }
        public EmailModel(string To,string Subject,string Content)
        {
            this.To = To;
            this.Subject = Subject;
            this.Content = Content;
        }
    }
}
