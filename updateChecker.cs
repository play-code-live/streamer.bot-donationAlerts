using System;
using System.Net;
using Newtonsoft.Json;
using System.Collections.Generic;


///----------------------------------------------------------------------------
///   Module:     DonationAlertsIntegration
///   Author:     play_code (https://twitch.tv/play_code)
///   Email:      info@play-code.live
///   Repository: https://github.com/play-code-live/streamer.bot-donationAlerts
///----------------------------------------------------------------------------
public class CPHInline
{
    private const double CurrentVersion = 0.6;
    private const string RepoReleasesAPIEndpoint = "https://api.github.com/repos/play-code-live/streamer.bot-donationAlerts/releases?per_page=100";

    public bool IsUpdateAvailable()
    {
        return GetNewerGitHubVersion(CurrentVersion) != null;
    }

    public bool CheckAndAnnounce()
    {
        var newerVersion = GetNewerGitHubVersion(CurrentVersion);
        if (newerVersion != null)
            CPH.SendMessage(string.Format("Доступно обновление интеграции с DonationAlerts. Версия {0} - {1}", newerVersion.TagName, newerVersion.HtmlUrl));

        return newerVersion != null;
    }

    private GitHubReleaseResponse GetNewerGitHubVersion(double currentVersion)
    {
        var newer = FetchLatestGitHubVersion();
        if (newer == null)
            return null;

        var numericVersion = Convert.ToDouble(newer.TagName.Substring(1).Replace('.', ','));
        CPH.LogDebug("UpdateChecker: Latest version = " + newer.TagName + " ("+numericVersion.ToString()+")");
        if (currentVersion >= numericVersion)
            return null;

        return newer;
    }

    private GitHubReleaseResponse FetchLatestGitHubVersion()
    {
        try
        {
            var releases = GetGitHubReleaseVersionsAsync();
            foreach (var release in releases)
            {
                if (release.IsDraft || release.IsPreRelease)
                    continue;

                return release;
            }
        }
        catch (Exception) {}

        return null;
    }

    private List<GitHubReleaseResponse> GetGitHubReleaseVersionsAsync()
    {
        try
        {
            WebClient webClient = new WebClient();
            webClient.Headers.Add("User-Agent", "StreamerBot DA Integration");
            Uri uri = new Uri(RepoReleasesAPIEndpoint);
            string releases = webClient.DownloadString(uri);

            return JsonConvert.DeserializeObject<List<GitHubReleaseResponse>>(releases);
        }
        catch (Exception) {}
        return new List<GitHubReleaseResponse>();
    }

    private class GitHubReleaseResponse
    {
        [JsonProperty("html_url")]
        public string HtmlUrl { get; set; }
        [JsonProperty("tag_name")]
        public string TagName { get; set; }
        [JsonProperty("name")]
        public string Name { get; set; }
        [JsonProperty("prerelease")]
        public bool IsPreRelease { get; set; }
        [JsonProperty("draft")]
        public bool IsDraft { get; set; }
    }
}