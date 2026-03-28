const { checkAuth } = require('./utils/auth');

exports.handler = async (event, context) => {
  // Autoriser uniquement les requêtes POST
  if (event.httpMethod !== 'POST') {
    return { statusCode: 405, body: 'Method Not Allowed' };
  }

  try {
    // 1. Vérification de l'authentification via le middleware adapté
    checkAuth(event);

    const { url: urlInput } = JSON.parse(event.body);
    if (!urlInput) {
      return { statusCode: 400, body: JSON.stringify({ error: "URL manquante" }) };
    }

    let url = urlInput.trim();
    if (!url.startsWith('http')) url = 'https://' + url;

    // 2. Configuration du timeout (10 secondes)
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 10000);

    const response = await fetch(url, { 
      method: 'GET', 
      signal: controller.signal,
      headers: { 'User-Agent': 'Mozilla/5.0 (compatible; SharinnganneBot/1.0)' }
    });
    clearTimeout(timeoutId);

    const html = await response.text();
    const lowerHtml = html.toLowerCase();
    const headers = response.headers;
    
    const result = { languages: [], web_servers: [], frameworks: [], cms: [], apis: [] };

    // 3. ANALYSE DES HEADERS & COOKIES
    const server = headers.get('server'); 
    const powered = headers.get('x-powered-by'); 
    const cookies = headers.get('set-cookie') || '';

    if (server) result.web_servers.push(server);
    if (powered) { 
      if(powered.includes('PHP')) result.languages.push('PHP'); 
      if(powered.includes('Express')) { result.languages.push('Node.js'); result.frameworks.push('Express'); } 
      if(powered.includes('ASP.NET')) result.languages.push('ASP.NET'); 
    }
    
    if (cookies.includes('PHPSESSID')) result.languages.push('PHP');
    if (cookies.includes('JSESSIONID')) result.languages.push('Java');
    if (cookies.includes('csrftoken')) result.languages.push('Python (Django?)');
    if (cookies.includes('laravel_session')) { result.languages.push('PHP'); result.frameworks.push('Laravel'); }

    // 4. ANALYSE DU HTML (SIGNATURES)
    if (lowerHtml.includes('wp-content') || lowerHtml.includes('generator" content="wordpress')) result.cms.push('WordPress');
    else if (lowerHtml.includes('shopify')) result.cms.push('Shopify');
    else if (lowerHtml.includes('wix.com')) result.cms.push('Wix');

    if (lowerHtml.includes('react') || lowerHtml.includes('data-reactroot')) result.frameworks.push('React');
    if (lowerHtml.includes('vue.js') || lowerHtml.includes('data-v-')) result.frameworks.push('Vue.js');
    if (lowerHtml.includes('jquery')) result.frameworks.push('jQuery');
    if (lowerHtml.includes('bootstrap')) result.frameworks.push('Bootstrap');
    if (lowerHtml.includes('tailwind')) result.frameworks.push('Tailwind CSS');

    if (lowerHtml.includes('google-analytics')) result.apis.push('Google Analytics');
    if (lowerHtml.includes('stripe.com') || lowerHtml.includes('paypal.com')) result.apis.push('Paiement (Stripe/PayPal)');
    if (lowerHtml.includes('/api/v1/') || lowerHtml.includes('/api/v2/') || lowerHtml.includes('/graphql')) result.apis.push('API Interne détectée');

    // Dédoublonnage des résultats
    Object.keys(result).forEach(k => result[k] = [...new Set(result[k])]);
    if (result.languages.length === 0) result.languages.push('Non identifié (HTML/JS statique ?)');

    return {
      statusCode: 200,
      body: JSON.stringify({ success: true, data: result }),
    };
  } catch (e) {
    return { statusCode: 500, body: JSON.stringify({ error: "Échec analyse: " + e.message }) };
  }
};