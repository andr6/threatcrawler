using System;

namespace ThreatCrawler
{
    internal class Item
    {
        public string Link { get; set; }
        public string Title { get; set; }
        public string Content { get; set; }
        public DateTime PublishDate { get; set; }
        public string Category { get; set; }
    }
}