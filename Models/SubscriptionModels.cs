using System;
using System.Collections.Generic;

namespace VPNProbe.Models;

public class SavedSubscription
{
    public string Name { get; set; } = "";
    public string Url { get; set; } = "";
    public DateTime SavedAt { get; set; } = DateTime.Now;
    public int ServerCount { get; set; }
}
