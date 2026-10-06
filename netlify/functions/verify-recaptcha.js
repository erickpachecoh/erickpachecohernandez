// netlify/functions/verify-recaptcha.js
// Verifica un token de reCAPTCHA contra la API de Google.

exports.handler = async (event) => {
  // Solo aceptar POST
  if (event.httpMethod !== 'POST') {
    return {
      statusCode: 405,
      body: JSON.stringify({ success: false, error: 'Method not allowed' }),
    };
  }

  // Leer la Secret Key desde variables de entorno
  const SECRET_KEY = process.env.SITE_RECAPTCHA_SECRET;

  if (!SECRET_KEY) {
    console.error('SITE_RECAPTCHA_SECRET no está configurada en Netlify');
    return {
      statusCode: 500,
      body: JSON.stringify({ success: false, error: 'Server misconfiguration' }),
    };
  }

  // Extraer el token del body
  let token;
  try {
    const body = JSON.parse(event.body || '{}');
    token = body.token;
  } catch (e) {
    return {
      statusCode: 400,
      body: JSON.stringify({ success: false, error: 'Invalid JSON' }),
    };
  }

  if (!token) {
    return {
      statusCode: 400,
      body: JSON.stringify({ success: false, error: 'Missing token' }),
    };
  }

  // Obtener la IP del cliente (mejora la verificación)
  const clientIp =
    event.headers['x-forwarded-for']?.split(',')[0].trim() ||
    event.headers['client-ip'] ||
    '';

  // Llamar a la API de Google
  try {
    const params = new URLSearchParams();
    params.append('secret', SECRET_KEY);
    params.append('response', token);
    if (clientIp) params.append('remoteip', clientIp);

    const googleRes = await fetch('https://www.google.com/recaptcha/api/siteverify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: params.toString(),
    });

    const data = await googleRes.json();

    // data.success = true si el captcha es válido
    if (!data.success) {
      console.warn('reCAPTCHA rechazado por Google:', data['error-codes']);
      return {
        statusCode: 200,
        body: JSON.stringify({
          success: false,
          errors: data['error-codes'] || [],
        }),
      };
    }

    return {
      statusCode: 200,
      body: JSON.stringify({ success: true }),
    };
  } catch (err) {
    console.error('Error al verificar reCAPTCHA:', err);
    return {
      statusCode: 500,
      body: JSON.stringify({ success: false, error: 'Verification failed' }),
    };
  }
};