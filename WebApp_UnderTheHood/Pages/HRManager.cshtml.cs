using System.Net.Http.Headers;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Newtonsoft.Json;
using WebApp_UnderTheHood.Authorization;
using WebApp_UnderTheHood.DTO;

namespace WebApp_UnderTheHood.Pages
{
    [Authorize(Policy = "HRManagerOnly")]
    public class HRManagerModel : PageModel
    {
        private readonly IHttpClientFactory _httpClientFactory;

        [BindProperty]
        public List<WeatherForecastDTO> weatherForecastItems { get; set; } = [];

        public HRManagerModel(IHttpClientFactory httpClientFactory)
        {
            _httpClientFactory = httpClientFactory;
        }

        public async Task OnGetAsync()
        {
            // get token from session
            var token = new JwtToken();

            var strTokenObj = HttpContext.Session.GetString("access_token");

            if (string.IsNullOrEmpty(strTokenObj))
            {
                token = await Authenticate();
            }
            else
            {
                token = JsonConvert.DeserializeObject<JwtToken>(strTokenObj) ?? new JwtToken();
            }

            if (token == null || string.IsNullOrWhiteSpace(token.AccessToken) || token.ExpiresAt <= DateTime.Now)
            {
               token = await Authenticate();
            }

            var httpClient = _httpClientFactory.CreateClient("OurWebAPI");

            httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token?.AccessToken ?? "");

            weatherForecastItems = await httpClient.GetFromJsonAsync<List<WeatherForecastDTO>>("WeatherForecast") ?? [];
        }

        private async Task<JwtToken> Authenticate()
        {
            var httpClient = _httpClientFactory.CreateClient("OurWebAPI");

            var authRes = await httpClient.PostAsJsonAsync("auth", new Credential { UserName = "admin", Password = "password" });
            authRes.EnsureSuccessStatusCode();

            var strJwt = await authRes.Content.ReadAsStringAsync();

            HttpContext.Session.SetString("access_token", strJwt);

            return JsonConvert.DeserializeObject<JwtToken>(strJwt) ?? new JwtToken();
        }
    }
}
